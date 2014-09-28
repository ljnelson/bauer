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

import java.util.logging.Level;
import java.util.logging.Logger;

import java.security.Permission;
import java.security.ProtectionDomain;

import javax.security.jacc.PolicyContextException;

public class DefaultPermissionEvaluator implements PermissionEvaluator {

  public DefaultPermissionEvaluator() {
    super();
  }

  @Override
  public PermissionEvaluation evaluate(final ProtectionDomain protectionDomain, final PolicyContext policyContext, final Permission permission) throws PolicyContextException {
    final String cn = this.getClass().getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "evaluate", new Object[] { "(protection domain)", policyContext, permission });
    }

    final PermissionEvaluation returnValue;
    if (policyContext == null) {
      returnValue = PermissionEvaluation.INDETERMINATE;

    } else if (policyContext.excludes(permission)) {
      returnValue = PermissionEvaluation.EXCLUDED;

    } else if (policyContext.mandates(permission)) {
      returnValue = PermissionEvaluation.MANDATED;

    } else if (policyContext.grants(permission, protectionDomain.getPrincipals())) {
      // Role-based permissions are granted explicitly to certain roles.
      returnValue = PermissionEvaluation.GRANTED; // non-authoritative response

    } else {
      // If we get here, then we neither granted nor denied the
      // permission, so indicate that to our caller, who will decide for
      // themselves according to defaults.
      returnValue = PermissionEvaluation.INDETERMINATE;

    }
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.exiting(cn, "evaluate", returnValue);
    }
    return returnValue;
  }

}
