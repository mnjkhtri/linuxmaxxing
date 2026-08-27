set pagination off
set confirm off
target remote :1235
hbreak debug_done
continue
printf "Mode: atomic amoadd.d\n"
printf "Expected: %d\n", 400000
printf "Actual:   %ld\n", *(long *)&shared_counter
detach
quit
