/***
 **  @(#) Vivastream.com
 **
 **  Copyright (c) 2015 Vivastream, LLC.  All Rights Reserved.
 **
 **
 **  THIS COMPUTER SOFTWARE IS THE PROPERTY OF Vivastream, LLC.
 **
 **  Permission is granted to use this software as specified by the VivaStream
 **  COMMERCIAL LICENSE AGREEMENT.  You may use this software only for
 **  commercial purposes, as specified in the details of the license.
 **  VIVASTREAM SHALL NOT BE LIABLE FOR ANY DAMAGES SUFFERED BY THE LICENSEE 
 **  AS A RESULT OF USING OR MODIFYING THIS SOFTWARE IN ANY WAY.
 **
 **  YOU MAY NOT DISTRIBUTE ANY SOURCE CODE OR OBJECT CODE FROM THE 
 **  VivaStream.com TOOLKIT AT ANY TIME. VIOLATORS WILL BE PROSECUTED TO THE 
 **  FULLEST EXTENT OF UNITED STATES LAW.
 **
 **  @version 1.0
 **  @author Copyright (c) 2015 Vivastream, LLC. All Rights Reserved.
 **
 **/
package com.vivastream.security.oauth2.provider;

public class UserDetailsAlreadyExistsException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public UserDetailsAlreadyExistsException(String message) {
        super(message);
    }

}
