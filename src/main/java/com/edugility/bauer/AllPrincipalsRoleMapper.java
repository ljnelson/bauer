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

import java.security.Principal;

import java.security.acl.Group;

import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import javax.security.jacc.PolicyContextException;

import com.edugility.bauer.RoleMapper;

/**
 * A {@link RoleMapper} that treats the {@linkplain
 * Principal#getName() names} of all non-{@link Group} {@link
 * Principal}s as role names.
 *
 * @see <a
 * href="https://github.com/picketbox/picketbox/blob/master/security-jboss-sx/jbosssx/src/main/java/org/jboss/security/jacc/ContextPolicy.java">the
 * <code>ContextPolicy</code> class from the PicketBox project</a>
 */
public class AllPrincipalsRoleMapper implements RoleMapper {

  /**
   * Creates a new {@link AllPrincipalsRoleMapper}.
   */
  public AllPrincipalsRoleMapper() {
    super();
  }

  /**
   * Returns a non-{@code null} {@link Set} of role names appropriate
   * for the supplied {@link Principal} array.
   *
   * <p>This implementation never returns {@code null}.</p>
   *
   * <p>This implementation adds the {@linkplain Principal#getName()
   * names} of all non-{@link Group} {@link Principal}s reachable from
   * the supplied {@link Principal} array to the {@link Set} that is
   * returned.  In systems where the <a
   * href="http://picketbox.jboss.org">PicketBox</a> project is
   * managing authorization, this approach should work (perhaps too
   * generously in some outlying cases).</p>
   *
   * @param principals an array of {@link Principal}s for which role
   * names should be returned; may be {@code null} in which case an
   * {@linkplain Collections#emptySet() empty <code>Set</code>} will
   * be returned
   *
   * @return a non-{@code null} {@link Set} of role names
   *
   * @exception PolicyContextException if an error occurs during role
   * mapping
   */
  public Set<String> getRoles(final Principal[] principals) throws PolicyContextException {
    Set<String> returnValue = null;
    if (principals != null && principals.length > 0) {
      returnValue = new HashSet<String>();
      for (final Principal p : principals) {
        if (p != null) {
          if (p instanceof Group) {
            final Enumeration<? extends Principal> members = ((Group)p).members();
            if (members != null) {
              while (members.hasMoreElements()) {
                final Principal member = members.nextElement();
                if (member != null) {
                  final String name = member.getName();
                  if (name != null) {
                    returnValue.add(name);
                  }
                }
              }
            }
          } else {
            final String name = p.getName();
            if (name != null) {
              returnValue.add(name);
            }
          }
        }
      }
    }
    if (returnValue == null) {
      returnValue = Collections.emptySet();
    }
    return returnValue;
  }

}
