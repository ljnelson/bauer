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
import java.security.Permissions;
import java.security.Principal;

import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyConfigurationFactory;
import javax.security.jacc.PolicyContextException;

public class ConfigurablePolicyContext extends AbstractPolicyContext implements Openable, PolicyConfiguration {

  public enum State {
    OPEN, IN_SERVICE, DELETED
  }

  private volatile Permissions excludedPolicy;

  private volatile Permissions uncheckedPolicy;

  private volatile Map<String, Permissions> perRolePolicy;

  private volatile State state;

  public ConfigurablePolicyContext(final String id) {
    super(id);
    this.open();
  }

  @Override
  public final PermissionCollection getExcludedPolicy() {
    checkInService();
    return this.excludedPolicy;
  }

  @Override
  public void addToExcludedPolicy(final Permission p) {
    final String cn = this.getClass().getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "addToExcludedPolicy", p);
    }

    this.getLock().writeLock().lock();
    try {
      checkOpen();
      if (p != null) {
        if (this.excludedPolicy == null) {
          this.excludedPolicy = new Permissions();
        }
        this.excludedPolicy.add(p);
      }
    } finally {
      this.getLock().writeLock().unlock();
    }
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.exiting(cn, "addToExcludedPolicy");
    }
  }

  @Override
  public void addToExcludedPolicy(final PermissionCollection p) {
    final String cn = this.getClass().getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "addToExcludedPolicy", p);
    }
    if (p != null) {
      synchronized (p) {
        final Enumeration<Permission> permissions = p.elements();
        if (permissions != null && permissions.hasMoreElements()) {
          this.getLock().writeLock().lock();
          try {
            checkOpen();
            if (this.excludedPolicy == null) {
              this.excludedPolicy = new Permissions();
            }
            while (permissions.hasMoreElements()) {
              final Permission permission = permissions.nextElement();
              if (permission != null) {
                this.excludedPolicy.add(permission);
              }
            }
          } finally {
            this.getLock().writeLock().unlock();
          }
        }
      }
    }
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.exiting(cn, "addToExcludedPolicy");
    }
  }

  @Override
  public final PermissionCollection getUncheckedPolicy() {
    checkInService();
    return this.uncheckedPolicy;
  }

  @Override
  public void addToUncheckedPolicy(final PermissionCollection p) {
    final String cn = this.getClass().getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "addToUncheckedPolicy", p);
    }
    if (p != null) {
      synchronized (p) {
        final Enumeration<Permission> permissions = p.elements();
        if (permissions != null && permissions.hasMoreElements()) {
          this.getLock().writeLock().lock();
          try {
            checkOpen();
            if (this.uncheckedPolicy == null) {
              this.uncheckedPolicy = new Permissions();
            }
            while (permissions.hasMoreElements()) {
              final Permission permission = permissions.nextElement();
              if (permission != null) {
                this.uncheckedPolicy.add(permission);
              }
            }
          } finally {
            this.getLock().writeLock().unlock();
          }
        }
      }
    }
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.exiting(cn, "addToUncheckedPolicy");
    }
  }

  @Override
  public void addToUncheckedPolicy(final Permission p) {
    final String cn = this.getClass().getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "addToUncheckedPolicy", p);
    }
    if (p != null) {
      this.getLock().writeLock().lock();
      try {
        checkOpen();
        if (this.uncheckedPolicy == null) {
          this.uncheckedPolicy = new Permissions();
        }
        this.uncheckedPolicy.add(p);
      } finally {
        this.getLock().writeLock().unlock();
      }
    }
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.exiting(cn, "addToUncheckedPolicy");
    }
  }

  @Override
  public final Map<? extends String, ? extends PermissionCollection> getRoles() {
    checkInService();
    return this.perRolePolicy;
  }

  @Override
  public void addToRole(final String roleName, final Permission p) {
    final String cn = this.getClass().getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "addToRole", new Object[] { roleName, p });
    }
    if (roleName != null && p != null) {
      this.getLock().writeLock().lock();
      try {
        checkOpen();
        if (this.perRolePolicy == null) {
          this.perRolePolicy = new HashMap<String, Permissions>();
        }
        Permissions permissions = this.perRolePolicy.get(roleName);
        if (permissions == null) {
          permissions = new Permissions();
          this.perRolePolicy.put(roleName, permissions);
        }
        permissions.add(p);
      } finally {
        this.getLock().writeLock().unlock();
      }
    }
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.exiting(cn, "addToRole");
    }
  }

  @Override
  public void addToRole(final String roleName, final PermissionCollection p) {
    final String cn = this.getClass().getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "addToRole", new Object[] { roleName, p });
    }
    if (roleName != null && p != null) {
      synchronized (p) {
        final Enumeration<Permission> permissions = p.elements();
        if (permissions != null && permissions.hasMoreElements()) {
          this.getLock().writeLock().lock();
          try {
            checkOpen();
            while (permissions.hasMoreElements()) {
              final Permission permission = permissions.nextElement();
              if (permission != null) {
                this.addToRole(roleName, permission);
              }
            }
          } finally {
            this.getLock().writeLock().unlock();
          }
        }
      }
    }
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.exiting(cn, "addToRole");
    }
  }

  @Override
  public void removeExcludedPolicy() {
    this.getLock().writeLock().lock();
    try {
      checkOpen();
      this.excludedPolicy = null;
    } finally {
      this.getLock().writeLock().unlock();
    }
  }

  @Override
  public void removeUncheckedPolicy() {
    this.getLock().writeLock().lock();
    try {
      checkOpen();
      this.uncheckedPolicy = null;
    } finally {
      this.getLock().writeLock().unlock();
    }
  }

  @Override
  public void removeRole(final String roleName) {
    if (roleName != null) {
      this.getLock().writeLock().lock();
      try {
        checkOpen();
        if (this.perRolePolicy != null) {
          if (this.perRolePolicy.remove(roleName) == null) {
            if (roleName.equals("*")) {
              this.perRolePolicy.clear();
            }
          }
        }
      } finally {
        this.getLock().writeLock().unlock();
      }
    }
  }

  @Override
  public void linkConfiguration(final PolicyConfiguration configuration) {
    final String cn = this.getClass().getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "linkConfiguration", configuration);
    }
    this.getLock().writeLock().lock();
    try {
      checkOpen();
    } finally {
      this.getLock().writeLock().unlock();
    }
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.exiting(cn, "linkConfiguration");
    }
  }

  @Override
  public void open() {
    this.getLock().writeLock().lock();
    try {
      this.state = State.OPEN;
    } finally {
      this.getLock().writeLock().unlock();
    }
  }

  @Override
  public void openAndClear() {
    this.getLock().writeLock().lock();
    try {
      this.delete();
      this.open();
    } finally {
      this.getLock().writeLock().lock();
    }
  }

  @Override
  public boolean isOpen() {
    this.getLock().readLock().lock();
    try {
      return this.state == State.OPEN;
    } finally {
      this.getLock().readLock().unlock();
    }
  }

  @Override
  public void delete() {
    final String cn = this.getClass().getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "delete");
    }
    this.getLock().writeLock().lock();
    try {
      this.removeExcludedPolicy();
      this.removeUncheckedPolicy();
      this.removeRole("*");
      this.state = State.DELETED;
    } finally {
      this.getLock().writeLock().unlock();
    }
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.exiting(cn, "delete");
    }
  }

  @Override
  public void commit() {
    final String cn = this.getClass().getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "commit");
    }
    this.getLock().writeLock().lock();
    try {
      checkNotDeleted();
      this.state = State.IN_SERVICE;
      if (logger != null && logger.isLoggable(Level.FINE)) {
        logger.logp(Level.FINE, cn, "commit", "Excluded policy: {0}", this.getExcludedPolicy());
        logger.logp(Level.FINE, cn, "commit", "Unchecked policy: {0}", this.getExcludedPolicy());
        logger.logp(Level.FINE, cn, "commit", "Role policies: {0}", this.getRoles());
        logger.logp(Level.FINE, cn, "commit", "Supported policy context handler keys: {0}", javax.security.jacc.PolicyContext.getHandlerKeys());
      }
    } finally {
      this.getLock().writeLock().unlock();
    }
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.exiting(cn, "commit");
    }
  }

  @Override
  public boolean inService() {
    this.getLock().readLock().lock();
    try {
      return this.state == State.IN_SERVICE;
    } finally {
      this.getLock().readLock().unlock();
    }
  }

  private final void checkOpen() {
    if (!this.isOpen()) {
      throw new IllegalStateException(String.valueOf(this.state));
    }
  }

  private final void checkInService() {
    if (!this.inService()) {
      throw new IllegalStateException(String.valueOf(this.state));
    }
  }

  private final void checkNotDeleted() {
    if (this.state == State.DELETED) {
      throw new IllegalStateException(String.valueOf(this.state));
    }
  }

  @Override
  public PermissionCollection getPermissions(final PermissionCollection delegatePolicyPermissions, final PermissionCollection protectionDomainPermissions, final Principal[] principals) throws PolicyContextException {
    PermissionCollection returnValue = null;
    this.getLock().readLock().lock();
    try {
      checkInService();
      returnValue = super.getPermissions(delegatePolicyPermissions, protectionDomainPermissions, principals);
    } finally {
      this.getLock().readLock().unlock();
    }
    return returnValue;
  }


}
