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

import java.util.Collection;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.Set;

import java.util.concurrent.CopyOnWriteArrayList;

import java.util.logging.Level;
import java.util.logging.Logger;

import java.security.Permission;
import java.security.ProtectionDomain;

import javax.security.jacc.PolicyContextException;

public class CompositePermissionEvaluator implements PermissionEvaluator {

  private final Collection<PermissionEvaluator> delegates;

  public CompositePermissionEvaluator() {
    super();
    this.delegates = new CopyOnWriteArrayList<PermissionEvaluator>();
  }

  public CompositePermissionEvaluator(final PermissionEvaluator delegate) {
    this();
    this.add(delegate);
  }

  public void add(final PermissionEvaluator delegate) {
    if (delegate != null && delegate != this) {
      this.delegates.add(delegate);
    }
  }

  @Override
  public PermissionEvaluation evaluate(final ProtectionDomain protectionDomain, final PolicyContext policyContext, final Permission permission) throws PolicyContextException {
    final String cn = this.getClass().getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "evaluate", new Object[] { "(protection domain)", policyContext, permission });
    }
    PermissionEvaluation returnValue = PermissionEvaluation.INDETERMINATE;

    if (!this.delegates.isEmpty()) {

      final Set<PermissionEvaluation> evaluations = EnumSet.noneOf(PermissionEvaluation.class);
      final Iterator<PermissionEvaluator> iterator = this.delegates.iterator();
      if (iterator != null) {
        while (iterator.hasNext()) {
          final PermissionEvaluator delegate = iterator.next();
          if (delegate != null) {
            final PermissionEvaluation evaluation = delegate.evaluate(protectionDomain, policyContext, permission);
            if (evaluation != null) {
              if (evaluation.equals(PermissionEvaluation.EVALUATOR_OUT_OF_SERVICE)) {
                iterator.remove();
              } else {
                evaluations.add(evaluation);
              }
            }
          }
        }
      }
      
      returnValue = this.consolidate(evaluations);
    }

    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.exiting(cn, "evaluate", returnValue);
    }
    return returnValue;
  }

  protected PermissionEvaluation consolidate(final Set<? extends PermissionEvaluation> evaluations) {
    final String cn = this.getClass().getName();
    final Logger logger = Logger.getLogger(cn);
    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.entering(cn, "consolidate", evaluations);
    }

    final PermissionEvaluation returnValue;
    if (evaluations == null || evaluations.isEmpty()) {
      returnValue = PermissionEvaluation.UNSUPPORTED;
    } else if (evaluations.contains(PermissionEvaluation.EXCLUDED)) {
      returnValue = PermissionEvaluation.EXCLUDED;
    } else if (evaluations.contains(PermissionEvaluation.MANDATED)) {
      returnValue = PermissionEvaluation.MANDATED;
    } else if (evaluations.contains(PermissionEvaluation.DENIED)) {
      if (evaluations.contains(PermissionEvaluation.GRANTED)) {
        returnValue = PermissionEvaluation.INDETERMINATE;
      } else {
        returnValue = PermissionEvaluation.DENIED;
      }
    } else if (evaluations.contains(PermissionEvaluation.GRANTED)) {
      returnValue = PermissionEvaluation.GRANTED;
    } else {
      returnValue = PermissionEvaluation.INDETERMINATE;
    }

    if (logger != null && logger.isLoggable(Level.FINER)) {
      logger.exiting(cn, "consolidate", returnValue);
    }
    return returnValue;
  }

}
