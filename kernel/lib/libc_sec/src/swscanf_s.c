/*
 * Copyright (c) Honor Device Co., Ltd. 2014-2018. All rights reserved.
 * Description: swscanf_s  function
 * Author: lishunda
 * Create: 2014-02-25
 */

#include "securec.h"

/*
 * <FUNCTION DESCRIPTION>
 *    The  swscanf_s  function  is  the  wide-character  equivalent  of the sscanf_s function
 *    The swscanf_s function reads data from buffer into the location given by
 *    each argument. Every argument must be a pointer to a variable with a type
 *    that corresponds to a type specifier in format. The format argument controls
 *    the interpretation of the input fields and has the same form and function
 *    as the format argument for the scanf function. If copying takes place between
 *    strings that overlap, the behavior is undefined.
 *
 * <INPUT PARAMETERS>
 *    buffer                 Stored data.
 *    format                 Format control string, see Format Specifications.
 *    ...                    Optional arguments.
 *
 * <OUTPUT PARAMETERS>
 *    ...                    the converted value stored in user assigned address
 *
 * <RETURN VALUE>
 *    Each of these functions returns the number of fields successfully converted
 *    and assigned; The return value does not include fields that were read but not
 *    assigned.
 *    A return value of 0 indicates that no fields were assigned.
 *    return -1 if an error occurs.
 */
int swscanf_s(const wchar_t *buffer, const wchar_t *format, ...)
{
    int ret;                    /* If initialization causes  e838 */
    va_list argList;

    va_start(argList, format);
    ret = vswscanf_s(buffer, format, argList);
    va_end(argList);
    (void)argList;              /* To clear e438 last value assigned not used , the compiler will optimize this code */

    return ret;
}


