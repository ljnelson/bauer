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

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyContextException;

/**
 * Something policy-related that can be notionally opened.
 *
 * <p>In the JACC specification, there is a requirement that a {@link
 * PolicyConfiguration} be opened when it is returned as a result of
 * the {@link
 * javax.security.jacc.PolicyConfigurationFactory#getPolicyConfiguration(String,
 * boolean)} method.  The mechanism for semantically opening a {@link
 * PolicyConfiguration}, however, is not exposed on the {@link
 * PolicyConfiguration} interface.  This interface can be used to
 * expose such functionality and is used by the {@link
 * PolicyConfigurationFactory}.</p>
 *
 * @see PolicyConfigurationFactory
 *
 * @see PolicyConfiguration
 */
public interface Openable {

  /**
   * Semantically opens this {@link Openable}.
   *
   * @exception PolicyContextException if an error occurs
   */
  public void open() throws PolicyContextException;

  public void openAndClear() throws PolicyContextException;

  /**
   * Returns {@code true} if this {@link Openable} is already open.
   *
   * @return {@code true} if this {@link Openable} is already open
   *
   * @exception PolicyContextException if an error occurs
   */
  public boolean isOpen() throws PolicyContextException;
  
}
