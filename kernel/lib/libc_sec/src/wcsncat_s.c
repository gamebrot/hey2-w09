/*
 * Copyright (c) Honor Device Co., Ltd. 2014-2018. All rights reserved.
 * Description: wcsncat_s  function
 * Author: lishunda
 * Create: 2014-02-25
 */

#include "securecutil.h"

/*
 * Befor this function, the basic parameter checking has been done
 */
SECUREC_INLINE errno_t SecDoCatLimitW(wchar_t *strDest, size_t destMax, const wchar_t *strSrc, size_t count)
{
    /* To calculate the length of a wide character, the parameter must be a wide character */
    size_t destLen;
    size_t srcLen;
    SECUREC_CALC_WSTR_LEN(strDest, destMax, &destLen);
    SECUREC_CALC_WSTR_LEN(strSrc, count, &srcLen);

    if (SECUREC_CAT_STRING_IS_OVERLAP(strDest, destLen, strSrc, srcLen)) {
        strDest[0] = L'\0';
        if (strDest + destLen <= strSrc && destLen == destMax) {
            SECUREC_ERROR_INVALID_PARAMTER("wcsncat_s");
            return EINVAL_AND_RESET;
        }
        SECUREC_ERROR_BUFFER_OVERLAP("wcsncat_s");
        return EOVERLAP_AND_RESET;
    }
    if (srcLen + destLen >= destMax || strDest == strSrc) {
        strDest[0] = L'\0';
        if (destLen == destMax) {
            SECUREC_ERROR_INVALID_PARAMTER("wcsncat_s");
            return EINVAL_AND_RESET;
        }
        SECUREC_ERROR_INVALID_RANGE("wcsncat_s");
        return ERANGE_AND_RESET;
    }
    SECUREC_MEMCPY_WARP_OPT(strDest + destLen, strSrc, srcLen * sizeof(wchar_t)); /* no  terminator */
    *(strDest + destLen + srcLen) = L'\0';
    return EOK;
}

/*
 * <FUNCTION DESCRIPTION>
 *    The wcsncat_s function appends not more than n successive wide characters
 *     (not including the terminating null wide character)
 *     from the array pointed to by strSrc to the end of the wide string pointed to by strDest.
 *
 *    The wcsncat_s function try to append the first D characters of strSrc to
 *    the end of strDest, where D is the lesser of count and the length of strSrc.
 *    If appending those D characters will fit within strDest (whose size is
 *    given as destMax) and still leave room for a null terminator, then those
 *    characters are appended, starting at the original terminating null of
 *    strDest, and a new terminating null is appended; otherwise, strDest[0] is
 *    set to the null character.
 *
 * <INPUT PARAMETERS>
 *    strDest               Null-terminated destination string.
 *    destMax               Size of the destination buffer.
 *    strSrc                Null-terminated source string.
 *    count                 Number of character to append, or truncate.
 *
 * <OUTPUT PARAMETERS>
 *    strDest               is updated
 *
 * <RETURN VALUE>
 *    EOK                   Success
 *    EINVAL                strDest is  NULL and destMax != 0 and destMax <= SECUREC_WCHAR_STRING_MAX_LEN
 *    EINVAL_AND_RESET      (strDest unterminated and all other parameters are valid) or
 *                    (strDest != NULL and strSrc is NULLL and destMax != 0 and destMax <= SECUREC_WCHAR_STRING_MAX_LEN)
 *    ERANGE                destMax > SECUREC_WCHAR_STRING_MAX_LEN or destMax is 0
 *    ERANGE_AND_RESET      strDest have not enough space  and all other parameters are valid  and not overlap
 *    EOVERLAP_AND_RESET     dest buffer and source buffer are overlapped and all  parameters are valid
 *
 *    If there is a runtime-constraint violation, strDest[0] will be set to the '\0' when strDest and destMax valid
 */
errno_t wcsncat_s(wchar_t *strDest, size_t destMax, const wchar_t *strSrc, size_t count)
{
    if (destMax == 0 || destMax > SECUREC_WCHAR_STRING_MAX_LEN) {
        SECUREC_ERROR_INVALID_RANGE("wcsncat_s");
        return ERANGE;
    }
    if (strDest == NULL || strSrc == NULL) {
        SECUREC_ERROR_INVALID_PARAMTER("wcsncat_s");
        if (strDest != NULL) {
            strDest[0] = L'\0';
            return EINVAL_AND_RESET;
        }
        return EINVAL;
    }
    if (count > SECUREC_WCHAR_STRING_MAX_LEN) {
#ifdef  SECUREC_COMPATIBLE_WIN_FORMAT
        if (count == ((size_t)-1)) {
            /* Windows internal functions may pass in -1 when calling this function */
            return SecDoCatLimitW(strDest, destMax, strSrc, destMax);
        }
#endif
        strDest[0] = L'\0';
        SECUREC_ERROR_INVALID_RANGE("wcsncat_s");
        return ERANGE_AND_RESET;
    }
    return SecDoCatLimitW(strDest, destMax, strSrc, count);
}


