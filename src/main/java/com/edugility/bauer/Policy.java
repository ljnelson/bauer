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

import java.security.CodeSource;
import java.security.Principal;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.ProtectionDomain;

import java.util.Iterator;
import java.util.ServiceLoader;

import java.util.concurrent.locks.ReadWriteLock;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.jacc.PolicyContextException;

public class Policy extends java.security.Policy {

  private static final ThreadLocal<Boolean> inImplies = new ThreadLocal<Boolean>() {
    @Override
    protected final Boolean initialValue() {
      return Boolean.FALSE;
    }
  };

  private final java.security.Policy delegate;

  private final Object evaluatorLock;

  private volatile PermissionEvaluator evaluator;

  public Policy() {
    super();
    this.evaluatorLock = new byte[0];
    this.delegate = java.security.Policy.getPolicy();
  }

  public PermissionEvaluator getPermissionEvaluator() {
    synchronized (this.evaluatorLock) {
      if (this.evaluator == null) {
        this.evaluator = this.createPermissionEvaluator();
      }
      return this.evaluator;
    }
  }

  public void setPermissionEvaluator(final PermissionEvaluator permissionEvaluator) {
    if (permissionEvaluator == null) {
      throw new IllegalArgumentException("permissionEvaluator", new NullPointerException("permissionEvaluator"));
    }
    synchronized (this.evaluatorLock) {
      this.evaluator = permissionEvaluator;
    }
  }

  private final PermissionEvaluator createPermissionEvaluator() {
    final String cn = this.getClass().getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "createPermissionEvaluator");
    }
    PermissionEvaluator permissionEvaluator = null;
    final ServiceLoader<PermissionEvaluator> permissionEvaluatorLoader = ServiceLoader.load(PermissionEvaluator.class);
    if (permissionEvaluatorLoader != null) {
      final Iterator<PermissionEvaluator> implementationsIterator = permissionEvaluatorLoader.iterator();
      if (implementationsIterator != null) {
        while (implementationsIterator.hasNext()) {
          if (permissionEvaluator == null) {
            permissionEvaluator = implementationsIterator.next();
          } else if (permissionEvaluator instanceof CompositePermissionEvaluator) {
            ((CompositePermissionEvaluator)permissionEvaluator).add(implementationsIterator.next());
          } else {
            final CompositePermissionEvaluator compositeEvaluator = new CompositePermissionEvaluator(permissionEvaluator);
            compositeEvaluator.add(implementationsIterator.next());
            permissionEvaluator = compositeEvaluator;
          }
        }
      }
    }
    if (permissionEvaluator == null) {
      permissionEvaluator = new DefaultPermissionEvaluator();
    }
    if (logger != null) {
      if (logger.isLoggable(Level.FINE)) {
        logger.logp(Level.FINE, cn, "createPermissionEvaluator", "Using PermissionEvaluator {0}", evaluator);
      }
      if (logger.isLoggable(Level.FINER)) {
        logger.exiting(cn, "createPermissionEvaluator", permissionEvaluator);
      }
    }
    return permissionEvaluator;
  }

  @Override
  public boolean implies(final ProtectionDomain domain, final Permission permission) {
    final String cn = this.getClass().getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "implies", new Object[] { "(protection domain)", permission });
    }

    final Boolean reentrant = inImplies.get();

    if (Boolean.TRUE.equals(reentrant)) {
      if (logger != null) {
        if (logger.isLoggable(Level.FINE)) {
          logger.logp(Level.FINE, cn, "implies", "Reentrant; returning true");
        }
        if (logger.isLoggable(Level.FINER)) {
          logger.exiting(cn, "implies", Boolean.TRUE);
        }
      }
      return true;

    } else {
      inImplies.set(Boolean.TRUE);

      try {
        PolicyContext policyContext = PolicyConfigurationFactory.getPolicyContext();
        if (logger != null && logger.isLoggable(Level.FINE)) {
          if (policyContext == null) {
            logger.logp(Level.FINE, cn, "implies", "Using default policy context");
          } else {
            logger.logp(Level.FINE, cn, "implies", "Using policy context {0}", policyContext);
          }
        }

        final PermissionEvaluator evaluator;
        synchronized (this.evaluatorLock) {
          evaluator = this.getPermissionEvaluator();
        }
        if (evaluator == null) {
          throw new SecurityException(new IllegalStateException("getPermissionEvaluator() == null", new NullPointerException("getPermissionEvaluator()")));
        }

        final ReadWriteLock lock = policyContext.getLock();
        PermissionEvaluation evaluation = null;
        try {
          if (lock != null) {
            lock.readLock().lock();
          }
          evaluation = evaluator.evaluate(domain, policyContext, permission);
        } catch (final PolicyContextException wrapMe) {
          throw new SecurityException(wrapMe);
        } finally {
          if (lock != null) {
            lock.readLock().unlock();
          }
        }

        if (logger != null && logger.isLoggable(Level.FINE)) {
          logger.logp(Level.FINE, cn, "implies", "Evaluation for permission {0}: {1}", new Object[] { permission, evaluation });
        }
        if (evaluation != null && !evaluation.equals(PermissionEvaluation.INDETERMINATE)) {
          final Boolean implies = evaluation.toBoolean();
          if (implies != null) {
            if (logger != null && logger.isLoggable(Level.FINER)) {
              logger.exiting(cn, "implies", implies);
            }
            return implies.booleanValue();
          }
        }

        // The permission was not authoritatively denied or granted.
        // Perhaps it's not our call to make (like an AWTPermission).  Ask
        // our delegate instead.
        if (this.delegate != null) {
          if (logger != null && logger.isLoggable(Level.FINE)) {
            logger.logp(Level.FINE, cn, "implies", "Indeterminate evaluation; consulting delegate Policy");
          }
          final boolean delegateImplication = this.delegate.implies(domain, permission);
          if (logger != null) {
            if (logger.isLoggable(Level.FINE)) {
              logger.logp(Level.FINE, cn, "implies", "Delegate policy {2} returned {0} from its implies() method for permission {1}", new Object[] { delegateImplication, permission, this.delegate });
            }
            if (logger.isLoggable(Level.FINER)) {
              logger.exiting(cn, "implies", delegateImplication);
            }
          }
          return delegateImplication;
        }

        if (logger != null && logger.isLoggable(Level.FINE)) {
          logger.logp(Level.FINE, cn, "implies", "No delegate Policy installed! Using superclass implication.");
        }

        // We tried everything we could think of, including delegation.
        // Simply do what our superclass does.
        final boolean superImplication = super.implies(domain, permission);
        if (logger != null && logger.isLoggable(Level.FINER)) {
          logger.exiting(cn, "implies", superImplication);
        }
        return superImplication;

      } finally {
        inImplies.set(Boolean.FALSE);
      }
    }
  }

  @Override
  public PermissionCollection getPermissions(final ProtectionDomain domain) {
    final String cn = this.getClass().getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "getPermissions", "(protection domain)");
    }
    final PermissionCollection returnValue;

    final PermissionCollection delegatePermissions;
    if (this.delegate == null) {
      delegatePermissions = null;
    } else {
      delegatePermissions = this.delegate.getPermissions(domain);
    }

    final PolicyContext policyContext = PolicyConfigurationFactory.getPolicyContext();
    if (policyContext == null) {
      returnValue = delegatePermissions;
    } else {
      final PermissionCollection domainPermissions;
      final Principal[] principals;
      if (domain == null) {
        domainPermissions = null;
        principals = null;
      } else {
        domainPermissions = domain.getPermissions();
        principals = domain.getPrincipals();
      }
      PermissionCollection pc = null;
      try {
        pc = policyContext.getPermissions(delegatePermissions, domainPermissions, principals);
      } catch (final PolicyContextException wrapMe) {
        throw new SecurityException(wrapMe);
      } finally {
        returnValue = pc;
      }
    }

    if (logger != null) {
      if (logger.isLoggable(Level.FINE)) {
        logger.logp(Level.FINE, cn, "getPermissions", "ProtectionDomain permissions: {0}", returnValue);
      }
      if (logger.isLoggable(Level.FINER)) {
        logger.exiting(cn, "getPermissions", returnValue);
      }
    }
    return returnValue;
  }

  @Override
  public PermissionCollection getPermissions(final CodeSource codeSource) {
    final String cn = this.getClass().getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "getPermissions", "(code source)");
    }

    final PermissionCollection returnValue;

    final PermissionCollection delegatePermissions;
    if (this.delegate == null) {
      delegatePermissions = null;
    } else {
      delegatePermissions = this.delegate.getPermissions(codeSource);
    }

    final PolicyContext policyContext = PolicyConfigurationFactory.getPolicyContext();
    if (policyContext == null) {
      returnValue = delegatePermissions;
    } else {
      PermissionCollection pc = null;
      try {
        pc = policyContext.getPermissions(delegatePermissions, null, null);
      } catch (final PolicyContextException wrapMe) {
        throw new SecurityException(wrapMe);
      } finally {
        returnValue = pc;
      }
    }

    if (logger != null) {
      if (logger.isLoggable(Level.FINE)) {
        logger.logp(Level.FINE, cn, "getPermissions", "CodeSource permissions: {0}", returnValue);
      }
      if (logger.isLoggable(Level.FINER)) {
        logger.exiting(cn, "getPermissions", returnValue);
      }
    }
    return returnValue;
  }

  @Override
  public void refresh() {
    final String cn = this.getClass().getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "refresh");
    }
    if (this.delegate != null) {
      this.delegate.refresh();
    }
    if (Boolean.parseBoolean(System.getProperty("java.security.Policy.supportsReuse", "true")) &&
        javax.security.jacc.PolicyContext.getHandlerKeys().contains("java.security.Policy.supportsReuse")) {
      try {
        javax.security.jacc.PolicyContext.getContext("java.security.Policy.supportsReuse");
      } catch (final PolicyContextException kaboom) {
        throw new SecurityException(kaboom);
      }
    }
    super.refresh();
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.exiting(cn, "refresh");
    }
  }

}
