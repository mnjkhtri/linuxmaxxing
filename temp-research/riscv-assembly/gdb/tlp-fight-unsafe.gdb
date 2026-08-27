set pagination off
set confirm off
target remote :1234
hbreak debug_done
continue
printf "Mode: unsafe load/add/store\n"
printf "Expected: %d\n", 400000
printf "Actual:   %ld\n", *(long *)&shared_counter
detach
quit
