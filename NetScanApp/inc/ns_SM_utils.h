#ifndef NS_SM_UTILS_H
#define NS_SM_UTILS_H

#include<cstdlib>
#include<cstring>
#include <sys/timeb.h>
#include <cstdint>
namespace NetScan_SM_Utils {

/*
You can print a chrono::timepoint like this:

auto t0 = std::chrono::high_resolution_clock::now();
auto nanosec = t0.time_since_epoch();

std::cout << nanosec.count() << " nanoseconds since epoch\n";
std::cout << nanosec.count() / (1000000000.0 * 60.0 * 60.0) << " hours since epoch\n";

*/
inline uint32_t get_ticks_passed_until_now(void)
{
    static struct timeb base_tick{};
    uint32_t       return_val{0};
    struct timeb cur_tick{};

    ftime(&cur_tick);

    if (cur_tick.millitm >= base_tick.millitm)
    {
        return_val = (cur_tick.millitm - cur_tick.millitm);
    }
    else
    {
        return_val = cur_tick.millitm + (1000 - base_tick.millitm);
    }

    memcpy(&base_tick, &cur_tick, sizeof(base_tick));



    /* return the ticks passed */
    return(return_val);
}
}


#endif // NS_SM_UTILS_H
