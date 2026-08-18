/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Tiny streaming JSON writer shared by the linuxmaxxing userspace observers.
 * It owns JSON syntax only: commas, nesting, escaping, and scalar serialization.
 * It knows nothing about any experiment, probe, or capture schema.
 * Output streams to a caller-provided FILE *; one NDJSON record ends with json_newline().
 */
#ifndef JSON_WRITER_H
#define JSON_WRITER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define JSON_WRITER_MAX_DEPTH 32

struct json_writer
{
	FILE *out;
	bool error;
	unsigned int depth;
	bool first[JSON_WRITER_MAX_DEPTH];
};

void json_writer_init(struct json_writer *jw, FILE *out);
bool json_writer_ok(const struct json_writer *jw);

/* Value-position opens: at the top level or as one element of an enclosing array. */
void json_object_begin(struct json_writer *jw);
void json_object_begin_field(struct json_writer *jw, const char *name);
void json_object_end(struct json_writer *jw);

void json_array_begin(struct json_writer *jw);
void json_array_begin_field(struct json_writer *jw, const char *name);
void json_array_end(struct json_writer *jw);

/* Member emission: all primitives carry a field name and live inside an object. */
void json_string(struct json_writer *jw, const char *name, const char *value);
void json_string_n(struct json_writer *jw, const char *name, const char *value, size_t max_len);
void json_u32(struct json_writer *jw, const char *name, uint32_t value);
void json_u64(struct json_writer *jw, const char *name, uint64_t value);
void json_i64(struct json_writer *jw, const char *name, int64_t value);
void json_bool(struct json_writer *jw, const char *name, bool value);
void json_null(struct json_writer *jw, const char *name);
void json_hex(struct json_writer *jw, const char *name, uint64_t value);

/* Project pointer convention: nonzero becomes "0x%016llx", zero becomes null. */
void json_ptr(struct json_writer *jw, const char *name, uint64_t value);

/* Value-position scalars: one element of an enclosing array. */
void json_u32_value(struct json_writer *jw, uint32_t value);
void json_u64_value(struct json_writer *jw, uint64_t value);
void json_i64_value(struct json_writer *jw, int64_t value);
void json_string_value(struct json_writer *jw, const char *value);
void json_string_n_value(struct json_writer *jw, const char *value, size_t max_len);
void json_bool_value(struct json_writer *jw, bool value);
void json_null_value(struct json_writer *jw);

void json_newline(struct json_writer *jw);

#endif /* JSON_WRITER_H */
