/*
 * Copyright (c) Honor Device Co., Ltd. 2014-2018. All rights reserved.
 * Description: scanf_s function
 * Author: lishunda
 * Create: 2014-02-25
 */

#include "securec.h"

/*
 * <FUNCTION DESCRIPTION>
 *    The scanf_s function is equivalent to fscanf_s with the argument stdin interposed before the arguments to scanf_s
 *     The scanf_s function reads data from the standard input stream stdin and
 *    writes the data into the location that's given by argument. Each argument
 *    must be a pointer to a variable of a type that corresponds to a type specifier
 *    in format. If copying occurs between strings that overlap, the behavior is
 *    undefined.
 *
 * <INPUT PARAMETERS>
 *    format                  Format control string.
 *    ...                       Optional arguments.
 *
 * <OUTPUT PARAMETERS>
 *    ...                       The converted value stored in user assigned address
 *
 * <RETURN VALUE>
 *    Returns the number of fields successfully converted and assigned;
 *    the return value does not include fields that were read but not assigned.
 *    A return value of 0 indicates that no fields were assigned.
 *    return -1 if an error occurs.
 */
int scanf_s(const char *format, ...)
{
    int ret;                    /* If initialization causes  e838 */
    va_list argList;

    va_start(argList, format);
    ret = vscanf_s(format, argList);
    va_end(argList);
    (void)argList;              /* To clear e438 last value assigned not used , the compiler will optimize this code */

    return ret;
}


