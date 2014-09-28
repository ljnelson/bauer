/* -*- mode: Java; c-basic-offset: 2; indent-tabs-mode: nil; coding: utf-8-unix -*-
 *
 * Copyright (c) 2014 Edugility LLC.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * The original copy of this license is available at
 * http://www.opensource.org/license/mit-license.html.
 */
package com.edugility.bauer;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyContextException;

/**
 * A {@link javax.security.jacc.PolicyConfigurationFactory}
 * implementation.
 *
 * @see javax.security.jacc.PolicyConfigurationFactory
 */
public class PolicyConfigurationFactory extends javax.security.jacc.PolicyConfigurationFactory {

  /**
   * A {@link ConcurrentMap} of {@link PolicyContext}s indexed by
   * their {@linkplain PolicyContext#getContextID() identifier}s.
   *
   * <p>This field is never {@code null}.</p>
   */
  private static final ConcurrentMap<String, PolicyContext> policyContexts = new ConcurrentHashMap<String, PolicyContext>();

  /**
   * Creates a new {@link PolicyConfigurationFactory}.
   */
  public PolicyConfigurationFactory() {
    super();
  }

  /**
   * Returns a non-{@code null} {@link PolicyConfiguration} in the
   * {@code open} state as mandated by the JACC specification,
   * possibly creating it in the process.
   *
   * <p>This method never returns {@code null}.  Overrides of this
   * method must not return {@code null} either.</p>
   *
   * @param policyContextId the identifier of a notional policy
   * context whose {@linkplain
   * #getPolicyConfigurationFor(PolicyContext) corresponding
   * <code>PolicyConfiguration</code>} should be returned; must not be
   * {@code null}
   *
   * @param remove whether to notionally "clear out" the returned
   * {@link PolicyConfiguration}
   *
   * @return a non-{@code null} {@link PolicyConfiguration} in the
   * <code>open</code> state
   *
   * @exception PolicyContextException if {@code policyContextId} is
   * {@code null} or if some other error occurs
   *
   * @see javax.security.jacc.PolicyConfigurationFactory#getPolicyConfiguration(String, boolean)
   *
   * @see #getPolicyConfigurationFor(PolicyContext)
   */
  @Override
  public PolicyConfiguration getPolicyConfiguration(final String policyContextId, final boolean remove) throws PolicyContextException {
    final String cn = this.getClass().getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "getPolicyConfiguration", new Object[] { policyContextId, remove });
    }

    if (policyContextId == null) {
      throw new PolicyContextException(new IllegalArgumentException("policyContextId", new NullPointerException("policyContextId")));
    }

    PolicyContext policyContext = policyContexts.get(policyContextId);
    if (policyContext == null) {

      policyContext = this.createPolicyContext(policyContextId);
      if (policyContext == null) {
        throw new PolicyContextException(new IllegalStateException("createPolicyContext(\"" + policyContextId + "\")", new NullPointerException("createPolicyContext(\"" + policyContextId + "\")")));
      }

      final PolicyContext oldPolicyContext = policyContexts.putIfAbsent(policyContextId, policyContext);
      if (oldPolicyContext != null) {
        // Race condition; someone beat us to it; use their value instead
        policyContext = oldPolicyContext;
      }

    }
    assert policyContext != null;

    final PolicyConfiguration policyConfiguration = this.getPolicyConfigurationFor(policyContext);
    if (policyConfiguration == null) {
      throw new PolicyContextException(new IllegalStateException("getPolicyConfigurationFor(com.edugility.bauer.PolicyContext)", new NullPointerException("getPolicyConfigurationFor(com.edugility.bauer.PolicyContext)")));
    }
    assert policyConfiguration instanceof Openable;
    final Openable openable = (Openable)policyConfiguration;

    if (remove) {
      openable.openAndClear();
    } else {
      openable.open();
    }
    if (!openable.isOpen()) {
      throw new PolicyContextException(new IllegalStateException("!policyConfiguration.isOpen()"));
    }

    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.exiting(cn, "getPolicyConfiguration", policyConfiguration);
    }
    return policyConfiguration;
  }

  protected PolicyContext createPolicyContext(final String policyContextId) {
    return new ConfigurablePolicyContext(policyContextId);
  }

  /**
   * Returns a non-{@code null} {@link PolicyConfiguration}
   * implementation suitable for configuring the supplied {@link
   * PolicyContext}.
   *
   * <p>This method never returns {@code null}.  Overrides of this
   * method must not return {@code null} either.</p>
   *
   * <p>This method does not do anything to change the state of the
   * returned {@link PolicyConfiguration} and overrides of this method
   * must not change its state either.</p>
   *
   * <p>The default implementation of this method checks to see if the
   * supplied {@link PolicyContext} implements {@link
   * PolicyConfiguration}.  If it does, then it is simply returned.
   * Otherwise a {@link PolicyContextException} is thrown.</p>
   *
   * @param policyContext the {@link PolicyContext} for which a
   * suitable {@link PolicyConfiguration} must be returned; may be
   * {@code null} in which case a {@link PolicyContextException} will
   * be thrown
   *
   * @return a non-{@code null} {@link PolicyConfiguration} suitable
   * for configuring the supplied {@link PolicyContext}; never {@code
   * null}
   *
   * @exception PolicyContextException if no suitable {@link
   * PolicyConfiguration} could be returned
   *
   * @see #getPolicyConfiguration(String, boolean)
   *
   * @see PolicyContext
   *
   * @see PolicyConfiguration
   */
  protected <T extends PolicyConfiguration & Openable> T getPolicyConfigurationFor(final PolicyContext policyContext) throws PolicyContextException {
    final String cn = this.getClass().getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "getPolicyConfigurationFor", policyContext);
    }
    if (policyContext instanceof PolicyConfiguration && policyContext instanceof Openable) {
      if (logger != null && logger.isLoggable(Level.FINER)) {
        logger.exiting(cn, "getPolicyConfigurationFor", policyContext);
      }
      @SuppressWarnings("unchecked")
      final T returnValue = (T)policyContext;
      return returnValue;
    }
    throw new PolicyContextException();
  }

  /**
   * Returns {@code true} if and only if a notional policy context
   * exists that corresponds to the supplied identifier and
   * {@linkplain #getPolicyConfigurationFor(PolicyContext) has a
   * corresponding <code>PolicyConfiguration</code>} whose {@link
   * PolicyConfiguration#inService()} method returns {@code true}.
   *
   * @param policyContextId the identifier of a notional policy
   * context; must not be {@code null}
   *
   * @return {@code true} if a corresponding {@link
   * PolicyConfiguration} is in service; {@code false} otherwise
   *
   * @exception PolicyContextException if {@code policyContextId} is
   * {@code null} or some other error occurs
   *
   * @see #getPolicyConfigurationFor(PolicyContext)
   *
   * @see PolicyConfiguration#inService()
   */
  @Override
  public boolean inService(final String policyContextId) throws PolicyContextException {
    if (policyContextId == null) {
      throw new PolicyContextException(new IllegalArgumentException("policyContextId", new NullPointerException("policyContextId")));
    }
    final boolean returnValue;
    final PolicyContext policyContext = policyContexts.get(policyContextId);
    if (policyContext == null) {
      returnValue = false;
    } else {
      final PolicyConfiguration policyConfiguration = this.getPolicyConfigurationFor(policyContext);
      returnValue = policyConfiguration != null && policyConfiguration.inService();
    }
    return returnValue;
  }

  public static final PolicyContext getPolicyContext(final String policyContextId) {
    final String cn = PolicyConfigurationFactory.class.getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "getPolicyContext", policyContextId);
      logger.logp(Level.FINER, cn, "getPolicyContext", "policyContextId: {0}", policyContextId);
    }
    final PolicyContext returnValue;
    if (policyContextId == null) {
      returnValue = null;
    } else {
      returnValue = policyContexts.get(policyContextId);
    }
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.exiting(cn, "getPolicyContext", returnValue);
    }
    return returnValue;
  }

  /**
   * Returns a {@link PolicyContext} that is currently in effect for
   * the caller.
   *
   * <p>This method may return {@code null}.</p>
   *
   * @return the {@link PolicyContext} that is currently in effect for
   * the caller, or {@code null}
   */
  public static final PolicyContext getPolicyContext() {
    return getPolicyContext(javax.security.jacc.PolicyContext.getContextID());
  }

}
