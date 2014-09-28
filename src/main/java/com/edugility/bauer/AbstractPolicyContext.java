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
import java.security.Permissions;
import java.security.PermissionCollection;
import java.security.Principal;

import java.security.acl.Group;

import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.jacc.PolicyContextException;

/**
 * A skeletal {@link PolicyContext} implementation.  {@link
 * PolicyContext} implementations should extend this class.
 *
 * <p>{@link AbstractPolicyContext} implementations must be safe for
 * use by concurrent threads.</p>
 *
 * @see PolicyContext
 */
public abstract class AbstractPolicyContext implements PolicyContext {

  /**
   * The identifier for this {@link AbstractPolicyContext}.
   *
   * <p>This field is never {@code null}.</p>
   */
  private final String id;

  private RoleMapper roleMapper;

  private final ReadWriteLock lock;

  /**
   * Creates a new {@link AbstractPolicyContext}.
   *
   * @param id the identifier for the new {@link
   * AbstractPolicyContext}; must not be {@code null}
   *
   * @exception IllegalArgumentException if {@code id} is {@code null}
   */
  protected AbstractPolicyContext(final String id) {
    super();
    if (id == null) {
      throw new IllegalArgumentException("id", new NullPointerException("id"));
    }
    this.id = id;
    this.lock = new ReentrantReadWriteLock();
    this.findRoleMapper();
  }

  protected void findRoleMapper() {
    final String name = System.getProperty("com.edugility.bauer.RoleMapper");
    if (name != null) {
      Class<?> c = null;
      try {
        c = this.loadClass(name);
      } catch (final ClassNotFoundException cnfe) {
        // TODO: log
      }
      if (c != null) {
        try {
          roleMapper = (RoleMapper)c.newInstance();
        } catch (final RuntimeException throwMe) {
          throw throwMe;
        } catch (final Exception everythingElse) {
          // ignore
        }
      }
    }
    if (roleMapper == null) {
      final ServiceLoader<RoleMapper> sl = ServiceLoader.load(RoleMapper.class);
      if (sl != null) {
        for (final RoleMapper rm : sl) {
          if (rm != null) {
            roleMapper = rm;
            break;
          }
        }
      }
    }
    if (roleMapper != null) {
      this.setRoleMapper(roleMapper);
    }
  }

  protected Class<?> loadClass(final String name) throws ClassNotFoundException {
    return Class.forName(name, true, Thread.currentThread().getContextClassLoader());
  }

  public RoleMapper getRoleMapper() {
    return this.roleMapper;
  }

  public void setRoleMapper(final RoleMapper roleMapper) {
    this.roleMapper = roleMapper;
  }

  @Override
  public ReadWriteLock getLock() {
    return this.lock;
  }

  /**
   * Returns the identifier for this {@link AbstractPolicyContext}.
   *
   * <p>This method never returns {@code null}.</p>
   *
   * @return a non-{@code null} identifier
   */
  @Override
  public final String getContextID() {
    return this.id;
  }

  /**
   * Invokes the {@link #getContextID()} method and returns its
   * result.
   *
   * <p>This method never returns {@code null}.</p>
   *
   * @return a non-{@code null} {@link String} representation of this
   * {@link AbstractPolicyContext}
   */
  @Override
  public String toString() {
    return this.getContextID();
  }

  @Override
  public Set<? extends String> getRoles(final Principal[] principals) throws PolicyContextException {
    final String cn = this.getClass().getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "getRoles", java.util.Arrays.toString(principals));
    }
    Set<String> returnValue = null;
    final RoleMapper roleMapper = this.getRoleMapper();
    if (roleMapper != null) {
      returnValue = roleMapper.getRoles(principals);
    }
    if (returnValue == null) {
      returnValue = Collections.emptySet();
    }
    if (logger != null) {
      if (logger.isLoggable(Level.FINE)) {
        logger.logp(Level.FINE, cn, "getRoles", "{0} --bound to roles--> {1}", new Object[] { java.util.Arrays.toString(principals), returnValue });
      }
    }
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.exiting(cn, "getRoles", returnValue);
    }
    return returnValue;
  }

 @Override
  public boolean mandates(final Permission p) throws PolicyContextException {
    final String cn = this.getClass().getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "mandates", p);
    }
    final boolean returnValue;
    if (p == null || this.excludes(p)) {
      returnValue = false;
    } else {
      this.getLock().readLock().lock();
      try {
        final PermissionCollection uncheckedPolicy = this.getUncheckedPolicy();
        returnValue = uncheckedPolicy != null && uncheckedPolicy.implies(p);
      } finally {
        this.getLock().readLock().unlock();
      }
    }
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.exiting(cn, "mandates", returnValue);
    }
    return returnValue;
  }

  @Override
  public boolean excludes(final Permission p) throws PolicyContextException {
    final String cn = this.getClass().getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "excludes", p);
    }
    final boolean returnValue;
    if (p == null) {
      returnValue = true;
    } else {
      boolean result = false;
      this.getLock().readLock().lock();
      try {
        final PermissionCollection excludedPolicy = this.getExcludedPolicy();
        if (excludedPolicy == null) {
          result = false;
        } else if (excludedPolicy.implies(p)) {
          result = true;
        } else {
          final Enumeration<Permission> excludedElements = excludedPolicy.elements();
          if (excludedElements == null || !excludedElements.hasMoreElements()) {
            result = false;
          } else {
            while (excludedElements.hasMoreElements()) {
              final Permission excludedElement = excludedElements.nextElement();
              if (excludedElement != null && p.implies(excludedElement)) {
                result = true;
                break;
              }
            }
          }
        }
      } finally {
        this.getLock().readLock().unlock();
        returnValue = result;
      }
    }
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.exiting(cn, "excludes", returnValue);
    }
    return returnValue;
  }

  @Override
  public boolean grants(final Permission suppliedPermission, final Principal[] principals) throws PolicyContextException {
    final String cn = this.getClass().getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "grants", new Object[] { suppliedPermission, java.util.Arrays.asList(principals) });
    }
    boolean returnValue = false;
    this.getLock().readLock().lock();    
    try {
      if (!this.excludes(suppliedPermission)) {
        Map<?, ? extends PermissionCollection> perRolePolicy = this.getRoles();
        if (perRolePolicy == null || perRolePolicy.isEmpty()) {
          // No perRolePolicy means there's nothing to grant.
          if (logger != null && logger.isLoggable(Level.FINER)) {
            logger.logp(Level.FINER, cn, "isGrantedToRole", "No role policy; returning false");
          }
        } else {
          // Authenticated principals with zero or more assigned roles.
          // Non-null perRolePolicy.  Time to check.
          final Collection<? extends String> roles = this.getRoles(principals);
          if (roles != null && !roles.isEmpty()) {
            boolean result = false;
            for (final String role : roles) {
              if (role != null) {
                final PermissionCollection rolePolicy = perRolePolicy.get(role);
                if (rolePolicy != null && rolePolicy.implies(suppliedPermission)) {
                  result = true;
                  break;
                }
              }
            }
            returnValue = result;
          }
        }
      }
    } finally {
      this.getLock().readLock().unlock();
    }
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.exiting(cn, "grants", returnValue);
    }
    return returnValue;
  }

  @Override
  public PermissionCollection getPermissions(final PermissionCollection delegatePolicyPermissions, final PermissionCollection protectionDomainPermissions, final Principal[] principals) throws PolicyContextException {
    final String cn = this.getClass().getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "getPermissions", new Object[] { delegatePolicyPermissions, protectionDomainPermissions, java.util.Arrays.toString(principals) });
    }

    final PermissionCollection returnValue = new Permissions();
    this.getLock().readLock().lock();
    try {
      if (delegatePolicyPermissions != null) {
        synchronized (delegatePolicyPermissions) {
          final Enumeration<Permission> elements = delegatePolicyPermissions.elements();
          if (elements != null) {
            while (elements.hasMoreElements()) {
              final Permission p = elements.nextElement();
              if (p != null && !this.excludes(p)) {
                returnValue.add(p);
              }
            }
          }
        }
      }

      if (protectionDomainPermissions != null) {
        synchronized (protectionDomainPermissions) {
          final Enumeration<Permission> elements = protectionDomainPermissions.elements();
          if (elements != null) {
            while (elements.hasMoreElements()) {
              final Permission p = elements.nextElement();
              if (p != null && !this.excludes(p)) {
                returnValue.add(p);
              }
            }
          }
        }
      }

      final PermissionCollection uncheckedPolicy = this.getUncheckedPolicy();
      if (uncheckedPolicy != null) {
        synchronized (uncheckedPolicy) {
          final Enumeration<Permission> elements = uncheckedPolicy.elements();
          if (elements != null) {
            while (elements.hasMoreElements()) {
              final Permission p = elements.nextElement();
              if (p != null && !this.excludes(p)) {
                returnValue.add(p);
              }
            }
          }
        }
      }

      if (principals != null && principals.length > 0) {
        final Collection<? extends String> roles = this.getRoles(principals);
        if (roles == null || roles.isEmpty()) {
          // TODO:
          // Principals that have no roles.
        } else {
          final Map<?, ? extends PermissionCollection> perRolePolicy = this.getRoles();
          if (perRolePolicy != null && !perRolePolicy.isEmpty()) {
            synchronized (perRolePolicy) {
              for (final String role : roles) {
                if (role != null) {
                  final PermissionCollection rolePermissions = perRolePolicy.get(role);
                  if (rolePermissions != null) {
                    final Enumeration<Permission> elements = rolePermissions.elements();
                    if (elements != null) {
                      while (elements.hasMoreElements()) {
                        final Permission p = elements.nextElement();
                        if (p != null && !this.excludes(p)) {
                          returnValue.add(p);
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }

      }

    } finally {
      this.getLock().readLock().unlock();
    }
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.exiting(cn, "getPermissions", returnValue);
    }
    return returnValue;
  }

}
