/*
 * Copyright (c) Honor Device Co., Ltd. 2014-2018. All rights reserved.
 * Description: fscanf_s function
 * Author: lishunda
 * Create: 2014-02-25
 */

#include "securec.h"

/*
 * <FUNCTION DESCRIPTION>
 *    The fscanf_s function is equivalent to fscanf except that the c, s,
 *    and [ conversion specifiers apply to a pair of arguments (unless assignment suppression is indicated by a*)
 *    The fscanf function reads data from the current position of stream into
 *    the locations given by argument (if any). Each argument must be a pointer
 *    to a variable of a type that corresponds to a type specifier in format.
 *    format controls the interpretation of the input fields and has the same
 *    form and function as the format argument for scanf.
 *
 * <INPUT PARAMETERS>
 *    stream              Pointer to FILE structure.
 *    format              Format control string, see Format Specifications.
 *    ...                 Optional arguments.
 *
 * <OUTPUT PARAMETERS>
 *    ...                 The convered value stored in user assigned address
 *
 * <RETURN VALUE>
 *    Each of these functions returns the number of fields successfully converted
 *    and assigned; the return value does not include fields that were read but
 *    not assigned. A return value of 0 indicates that no fields were assigned.
 *    return -1 if an error occurs.
 */
int fscanf_s(FILE *stream, const char *format, ...)
{
    int ret;                    /* If initialization causes  e838 */
    va_list argList;

    va_start(argList, format);
    ret = vfscanf_s(stream, format, argList);
    va_end(argList);
    (void)argList;              /* To clear e438 last value assigned not used , the compiler will optimize this code */

    return ret;
}


