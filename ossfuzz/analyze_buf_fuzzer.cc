/*
 * OSS-Fuzz target for analyze_buf bulk-extractor API function
 */

#include "../config.h"

#include "bulk_extractor_api.h"

extern "C" {

int LLVMFuzzerTestOneInput(const uint8_t *data,
                           size_t size)
{
	BEFILE *file = NULL;

	file = bulk_extractor_open(0, NULL);
	if(file == NULL) {
		return 0;
	}
	bulk_extractor_analyze_buf(file, (uint8_t *) data, size);

	bulk_extractor_close(file);

	return 0;
}

} /* extern "C" */

