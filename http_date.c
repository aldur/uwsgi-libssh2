#include "http_date.h"

time_t uwsgi_parse_http_date(char *date, uint16_t len) {
			struct tm hdtm;

			if (len != 29 && date[3] != ',')
					return 0;

			hdtm.tm_mday = uwsgi_str2_num(date + 5);

			switch (date[8]) {
			case 'J':
					if (date[9] == 'a') {
							hdtm.tm_mon = 0;
							break;
					}

					if (date[9] == 'u') {
							if (date[10] == 'n') {
									hdtm.tm_mon = 5;
									break;
							}

							if (date[10] == 'l') {
									hdtm.tm_mon = 6;
									break;
							}

							return 0;
					}

					return 0;

			case 'F':
					hdtm.tm_mon = 1;
					break;

			case 'M':
					if (date[9] != 'a')
							return 0;

					if (date[10] == 'r') {
							hdtm.tm_mon = 2;
							break;
					}

					if (date[10] == 'y') {
							hdtm.tm_mon = 4;
							break;
					}

					return 0;

			case 'A':
					if (date[10] == 'r') {
							hdtm.tm_mon = 3;
							break;
					}
					if (date[10] == 'g') {
							hdtm.tm_mon = 7;
							break;
					}
					return 0;

			case 'S':
					hdtm.tm_mon = 8;
					break;

			case 'O':
					hdtm.tm_mon = 9;
					break;

			case 'N':
					hdtm.tm_mon = 10;
			break;

			case 'D':
					hdtm.tm_mon = 11;
					break;
			default:
					return 0;
			}

			hdtm.tm_year = uwsgi_str4_num(date + 12) - 1900;

			hdtm.tm_hour = uwsgi_str2_num(date + 17);
			hdtm.tm_min = uwsgi_str2_num(date + 20);
			hdtm.tm_sec = uwsgi_str2_num(date + 23);

			return timegm(&hdtm);
}
