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

import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Principal;

import java.util.Map;
import java.util.Set;

import java.util.concurrent.locks.ReadWriteLock;

import javax.security.jacc.PolicyContextException;

/**
 * A notionally immutable collection of notional <em>policy
 * statements</em> (represented by {@link PermissionCollection}s) that
 * collectively describe what permissions may be authorized in a
 * particular operational environment.
 *
 * <p>{@link PolicyContext} implementations must be safe for use by
 * concurrent threads.</p>
 *
 * <h2>Design Notes</h2>
 *
 * <p>A policy context, in the ontology of the JACC specification, is
 * a non-standardized concept that is the set of rules by which
 * authorization decisions get made.  If you think of it as a black
 * box whose configuration functionality is exposed via the {@link
 * PolicyConfiguration} interface, and whose decision-making apparatus
 * is reachable through the {@link Policy#implies(ProtectionDomain,
 * Permission)} method, then you can see that trying to standardize
 * its many possible implementations is a fruitless exercise.</p>
 *
 * <p>We might think about what a {@link PolicyContext} can
 * <em>do</em>.  We know right away that it itself cannot be
 * configured, or at least that that is not its primary function.  So
 * methods that start with {@code add} or {@code set} and so on should
 * not belong to this interface.</p>
 *
 * <p>The act of granting a permission is technically performed by the
 * {@link Policy} itself, within the notional context formed by
 * whatever a policy context is.  So a policy context iself doesn't
 * really grant permissions either.</p>
 *
 * <p>One of the central notions of a policy context is that it
 * contains enough information to allow permissions to be
 * (semantically) definitively <em>excluded</em>, or <em>denied</em>
 * by the {@link Policy} performing enforcement.  That can't really be
 * expressed by the {@link Policy#implies(ProtectionDomain,
 * Permission)} method.</p>
 *
 * <p>So it's smelling like perhaps we need a new interface that would
 * feature a {@code grants} and {@code exlcudes} method.  I think from
 * there we might be able to fill in a lot of other boilerplate stuff
 * that JACC implementors really shouldn't have to worry about.</p>
 *
 * @see javax.security.jacc.PolicyConfiguration
 *
 * @see AbstractPolicyContext
 *
 * @see ConfigurablePolicyContext
 */
public interface PolicyContext {

  /**
   * Returns the identifier of this {@link PolicyContext}.
   *
   * <p>Implementations of this method must not return {@code
   * null}.</p>
   *
   * @return a non-{@code null} identifier
   */
  public String getContextID();

  public ReadWriteLock getLock();

  /**
   * Returns an immutable {@link PermissionCollection} representing
   * permissions that should be authorized regardless of environmental
   * factories.
   *
   * <p>This method may return {@code null}.</p>
   *
   * @return a {@link PermissionCollection}, or {@code null}
   *
   * @exception PolicyContextException if an error occurs
   */
  public PermissionCollection getUncheckedPolicy() throws PolicyContextException;

  /**
   * Returns an immutable {@link PermissionCollection} representing
   * permissions that should not be authorized regardless of
   * environmental factories.
   *
   * <p>This method may return {@code null}.</p>
   *
   * @return a {@link PermissionCollection}, or {@code null}
   *
   * @exception PolicyContextException if an error occurs
   */
  public PermissionCollection getExcludedPolicy() throws PolicyContextException;

  /**
   * Returns an immutable {@link Map} of {@link PermissionCollection}s
   * representing permissions that should be authorized indexed by the
   * role names to which they apply.
   *
   * <p>This method may return {@code null}.</p>
   *
   * @return a {@link Map} of role-indexed {@link
   * PermissionCollection}s, or {@code null}
   *
   * @exception PolicyContextException if an error occurs
   */
  public Map<? extends String, ? extends PermissionCollection> getRoles() throws PolicyContextException;

  public PermissionCollection getPermissions(final PermissionCollection delegatePolicyPermissions, final PermissionCollection protectionDomainPermissions, final Principal[] principals) throws PolicyContextException;

  public boolean excludes(final Permission p) throws PolicyContextException;
  
  public boolean mandates(final Permission p) throws PolicyContextException;

  public boolean grants(final Permission suppliedPermission, final Principal[] principals) throws PolicyContextException;
  
  public Set<? extends String> getRoles(final Principal[] principals) throws PolicyContextException;

}
