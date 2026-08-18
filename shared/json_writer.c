/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <string.h>
#include "json_writer.h"

static void jw_putc(struct json_writer *jw, int c)
{
	if (jw->error)
		return;
	if (fputc(c, jw->out) == EOF)
		jw->error = true;
}

static void jw_puts(struct json_writer *jw, const char *s)
{
	if (jw->error)
		return;
	if (fputs(s, jw->out) == EOF)
		jw->error = true;
}

/* Insert a comma before every item after the first one inside the current container. */
static void jw_comma(struct json_writer *jw)
{
	if (jw->depth == 0)
		return;
	if (jw->first[jw->depth - 1])
		jw->first[jw->depth - 1] = false;
	else
		jw_putc(jw, ',');
}

static void jw_put_escaped(struct json_writer *jw, const char *value, size_t max_len)
{
	jw_putc(jw, '"');
	for (size_t i = 0; i < max_len && value[i]; i++)
	{
		unsigned char c = (unsigned char)value[i];

		if (c == '"' || c == '\\')
		{
			jw_putc(jw, '\\');
			jw_putc(jw, c);
		}
		else if (c < 0x20)
		{
			char buf[8];

			snprintf(buf, sizeof(buf), "\\u%04x", c);
			jw_puts(jw, buf);
		}
		else
		{
			jw_putc(jw, c);
		}
	}
	jw_putc(jw, '"');
}

/* Caller-provided field name, a NUL-terminated identifier/literal. */
static void jw_name(struct json_writer *jw, const char *name)
{
	jw_put_escaped(jw, name, SIZE_MAX);
	jw_putc(jw, ':');
}

void json_writer_init(struct json_writer *jw, FILE *out)
{
	jw->out = out;
	jw->error = false;
	jw->depth = 0;
	memset(jw->first, 0, sizeof(jw->first));
}

bool json_writer_ok(const struct json_writer *jw)
{
	return !jw->error;
}

void json_object_begin(struct json_writer *jw)
{
	jw_comma(jw);
	jw_putc(jw, '{');
	if (jw->depth < JSON_WRITER_MAX_DEPTH)
		jw->first[jw->depth++] = true;
	else
		jw->error = true;
}

void json_object_begin_field(struct json_writer *jw, const char *name)
{
	jw_comma(jw);
	jw_name(jw, name);
	jw_putc(jw, '{');
	if (jw->depth < JSON_WRITER_MAX_DEPTH)
		jw->first[jw->depth++] = true;
	else
		jw->error = true;
}

void json_object_end(struct json_writer *jw)
{
	jw_putc(jw, '}');
	if (jw->depth > 0)
		jw->depth--;
}

void json_array_begin(struct json_writer *jw)
{
	jw_comma(jw);
	jw_putc(jw, '[');
	if (jw->depth < JSON_WRITER_MAX_DEPTH)
		jw->first[jw->depth++] = true;
	else
		jw->error = true;
}

void json_array_begin_field(struct json_writer *jw, const char *name)
{
	jw_comma(jw);
	jw_name(jw, name);
	jw_putc(jw, '[');
	if (jw->depth < JSON_WRITER_MAX_DEPTH)
		jw->first[jw->depth++] = true;
	else
		jw->error = true;
}

void json_array_end(struct json_writer *jw)
{
	jw_putc(jw, ']');
	if (jw->depth > 0)
		jw->depth--;
}

void json_string(struct json_writer *jw, const char *name, const char *value)
{
	jw_comma(jw);
	jw_name(jw, name);
	jw_put_escaped(jw, value, SIZE_MAX);
}

void json_string_n(struct json_writer *jw, const char *name, const char *value, size_t max_len)
{
	jw_comma(jw);
	jw_name(jw, name);
	jw_put_escaped(jw, value, max_len);
}

void json_u32(struct json_writer *jw, const char *name, uint32_t value)
{
	jw_comma(jw);
	jw_name(jw, name);
	char buf[16];

	snprintf(buf, sizeof(buf), "%u", value);
	jw_puts(jw, buf);
}

void json_u64(struct json_writer *jw, const char *name, uint64_t value)
{
	jw_comma(jw);
	jw_name(jw, name);
	char buf[24];

	snprintf(buf, sizeof(buf), "%llu", (unsigned long long)value);
	jw_puts(jw, buf);
}

void json_bool(struct json_writer *jw, const char *name, bool value)
{
	jw_comma(jw);
	jw_name(jw, name);
	jw_puts(jw, value ? "true" : "false");
}

void json_null(struct json_writer *jw, const char *name)
{
	jw_comma(jw);
	jw_name(jw, name);
	jw_puts(jw, "null");
}

void json_ptr(struct json_writer *jw, const char *name, uint64_t value)
{
	jw_comma(jw);
	jw_name(jw, name);
	if (value)
	{
		char buf[32];

		snprintf(buf, sizeof(buf), "\"0x%016llx\"", (unsigned long long)value);
		jw_puts(jw, buf);
	}
	else
	{
		jw_puts(jw, "null");
	}
}

void json_newline(struct json_writer *jw)
{
	jw_putc(jw, '\n');
}
