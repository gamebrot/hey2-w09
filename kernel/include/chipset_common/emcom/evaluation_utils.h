/*
* Copyright (c) Honor Device Co., Ltd. 2018-2020. All rights reserved.
* Description: utility functions for network evaluation
* Author: dengyu davy.deng.
* Create: 2018-02-13
*/

#ifndef _EVALUATION_UTILS_H_
#define _EVALUATION_UTILS_H_

/* include files */
#include "evaluation_common.h"

/* calculation related macro */
#define PROB_CONVERT_COUNT(x1, y1, z1, x2, y2, z2, x3, y3, z3) \
	{{ (x1 * RTT_COUNT / 100), (y1 * RTT_COUNT / 100), (z1 * RTT_COUNT / 100) }, \
	{ (x2 * RTT_COUNT / 100), (y2 * RTT_COUNT /100), (z2 * RTT_COUNT /100) }, \
	{ (x3 * RTT_COUNT / 100), (y3 * RTT_COUNT / 100), (z3 * RTT_COUNT /100) }}
/* validate parameters */
#define VALIDATE_NETWORK_TYPE(parameter) \
	(NETWORK_TYPE_UNKNOWN == parameter \
	|| NETWORK_TYPE_2G == parameter \
	|| NETWORK_TYPE_3G == parameter \
	|| NETWORK_TYPE_4G == parameter \
	|| NETWORK_TYPE_WIFI == parameter)
#define VALIDATE_BOTTLENECK(parameter) \
	(NETWORK_BOTTLENECK_UNKNOWN == parameter \
	|| NETWORK_BOTTLENECK_SIGNAL == parameter \
	|| NETWORK_BOTTLENECK_TRAFFIC == parameter \
	|| NETWORK_BOTTLENECK_STABILITY == parameter \
	|| NETWORK_BOTTLENECK_NONE == parameter)
#define VALIDATE_QUALITY(parameter) \
	(NETWORK_QUALITY_UNKNOWN == parameter \
	|| NETWORK_QUALITY_GOOD == parameter \
	|| NETWORK_QUALITY_NORMAL == parameter \
	|| NETWORK_QUALITY_BAD == parameter)

/* misc values */
#define SIGNAL_ABNORMAL_THRESHOLD (-100)
#define RTT_ABNORMAL_THRESHOLD 400

/* index levels, IG means INDEX_GOOD, note it begins from 0 */
typedef enum {
	LEVEL_GOOD,
	LEVEL_NORMAL,
	LEVEL_BAD,
	LEVEL_MAX,
} index_quality;
#define INDEX_QUALITY_LEVELS    LEVEL_MAX

/* constants and structures used in signal strength evaluation */
/* number of signal strength interval endpoints, for instance, 3 levels require 4 endpoints */
#define SS_ENDPOINTS (INDEX_QUALITY_LEVELS + 1)

/* constants and structures used in traffic deduction */
#define TRAFFIC_SS_SEGMENTS 3
#define TRAFFIC_SS_SEGMENT_ENDPOINTS (TRAFFIC_SS_SEGMENTS + 1)

/* point related definitions */
#define POINT_DIMENSIONS 3
#define RTT_POINT_ENDPOINTS (POINT_DIMENSIONS + 1)

typedef struct { // 3-dimension point. coordinates are COUNTS IN DIFFERENT SEGMENTS
	int8_t x;
	int8_t y;
	int8_t z;
} point;

#define INVALID_POINT { INVALID_VALUE, INVALID_VALUE, INVALID_VALUE }
#define VALIDATE_POINT(pt) (pt.x >= 0 && pt.x <= 100 && pt.y >= 0 \
							&& pt.y <= 100 && pt.z >= 0 && pt.z <= 100)
#define INDEX_X 0
#define INDEX_Y 1
#define INDEX_Z 2
typedef struct {
	point good_point;
	point normal_point;
	point bad_point;
} point_set;

#define POINT_CONVERT_PERCENT_TO_COUNT(p1, p2, len) p1.x = (p2.x * len) / 100;\
														p1.y = (p2.y * len) / 100;\
														p1.z = (p2.z * len) / 100

/* constants and structures used in stability evaluation */
#define STABILITY_RTT_SEGMENT_ENDPOINTS 5
#define STABILITY_RTT_FINE_STDEV_ENDPOINTS       5

/* function declarations */
void cal_statistics(const int32_t* array, const int8_t length, int32_t* avg, int32_t* stdev);
point get_space_point(int32_t* array, int8_t length,
							const int32_t* segment_ends, int8_t endpoints);
int8_t cal_traffic_index(int8_t network_type, int32_t signal_strength,
							int32_t* rtt_array, int8_t rtt_array_length);
int8_t cal_rtt_stability_index(int8_t network_type, int32_t avg, int32_t sqrdev);

#endif // _EVALUATION_UTILS_H_