#!/usr/bin/env bash

set -euo pipefail

mode=${1:-}
ROOT_DIR=$(dirname "$(realpath "$0")")
config_file=${CONFIG_FILE:-$ROOT_DIR/build/.config}

if [ -z "$mode" ]; then
	printf 'usage: %s {none|core|mm|vfs}\n' "$0" >&2
	exit 2
fi

if [ ! -f "$config_file" ]; then
	printf 'missing config file: %s\n' "$config_file" >&2
	exit 1
fi

disable_all_modes()
{
	"$ROOT_DIR/linux/scripts/config" --file "$config_file" --disable KOOPS_STUDY_NONE
	"$ROOT_DIR/linux/scripts/config" --file "$config_file" --disable KOOPS_KERNEL_LOGS
	"$ROOT_DIR/linux/scripts/config" --file "$config_file" --disable KOOPS_MM_LOGS
	"$ROOT_DIR/linux/scripts/config" --file "$config_file" --disable KOOPS_VFS_LOGS
}

disable_all_modes

case "$mode" in
	none)
		"$ROOT_DIR/linux/scripts/config" --file "$config_file" --enable KOOPS_STUDY_NONE
		;;
	core)
		"$ROOT_DIR/linux/scripts/config" --file "$config_file" --enable KOOPS_KERNEL_LOGS
		;;
	mm)
		"$ROOT_DIR/linux/scripts/config" --file "$config_file" --enable KOOPS_MM_LOGS
		;;
	vfs)
		"$ROOT_DIR/linux/scripts/config" --file "$config_file" --enable KOOPS_VFS_LOGS
		;;
	*)
		printf 'unknown study mode: %s\n' "$mode" >&2
		printf 'usage: %s {none|core|mm|vfs}\n' "$0" >&2
		exit 2
		;;
esac

make -C "$ROOT_DIR/linux" O="$ROOT_DIR/build" olddefconfig
