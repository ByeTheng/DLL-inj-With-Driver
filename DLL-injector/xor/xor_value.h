#pragma once

int mini_ttoi(const char* str)
{
	int ret = xor_value_1(0);
	while (*str >= '0' && *str <= '9')
	{
		ret *= xor_value_1(10);
		ret += *str - '0';
		str++;
	}
	return ret;
}

#define xor_int(v) [&](){ return mini_ttoi(xor_a(#v)); \
	}()