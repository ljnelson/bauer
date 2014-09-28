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

public enum PermissionEvaluation {

  /**
   * A {@link PermissionEvaluation} indicating that whatever component
   * it was that returned it can be taken permanently out of service.
   */
  EVALUATOR_OUT_OF_SERVICE(null, false),
    
  UNSUPPORTED(null, false),

  INDETERMINATE(null, false),

  DENIED(Boolean.FALSE, false),

  EXCLUDED(Boolean.FALSE, true),

  GRANTED(Boolean.TRUE, false),

  MANDATED(Boolean.TRUE, true);

  private Boolean booleanValue;

  private boolean authoritative;

  PermissionEvaluation(final Boolean booleanValue, final boolean authoritative) {
    this.booleanValue = booleanValue;
    this.authoritative = authoritative;
  }

  public boolean isAuthoritative() {
    return this.authoritative;
  }

  public Boolean toBoolean() {
    return this.booleanValue;
  }

}
