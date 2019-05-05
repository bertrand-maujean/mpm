#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
extern int msg_current_lang;
extern int msg_default_lang;
char *msg_get_string(int id);
#define _MSG(id) (&msg_data[msg_index[MSG_NB_LANG*id + msg_current_lang]])


// Définition des codes de langue
#define MSG_NB_LANG 2
extern const char *msg_codes_lang[];


// Définition des ids de message
#define MSG_NB_ID 84

#define MSG_CHDIR 0
#define MSG_CHECK1 1
#define MSG_CHECK2 2
#define MSG_CHECK3 3
#define MSG_CHECK4 4
#define MSG_CHECK5 5
#define MSG_CHECK6 6
#define MSG_CHECK7 7
#define MSG_CHECK_CHANGED1 8
#define MSG_CHECK_JUST_ENOUGH 9
#define MSG_CHECK_NB1 10
#define MSG_CHECK_NBP 11
#define MSG_CHECK_WARN 12
#define MSG_CHECK_WARN_FIRST 13
#define MSG_CWD 14
#define MSG_DELETE_ID 15
#define MSG_DELETE_ID2 16
#define MSG_DELETE_ID3 17
#define MSG_DELETE_ID4 18
#define MSG_DEL_HOLD1 19
#define MSG_DEL_HOLD2 20
#define MSG_DEL_HOLD_OK 21
#define MSG_EDSEC1 22
#define MSG_EDSEC2 23
#define MSG_EDSEC3 24
#define MSG_EDSEC4 25
#define MSG_EDSEC5 26
#define MSG_ED_SEC_TITLE 27
#define MSG_ED_SEC_TITLE2 28
#define MSG_EMPTY 29
#define MSG_ERREUR_OPEN_FILE 30
#define MSG_ERROR_FEW_DIS_PARTS 31
#define MSG_ERROR_NO_DB 32
#define MSG_ERROR_NO_DB2 33
#define MSG_ERROR_SCOLON 34
#define MSG_ERR_DB_ALREADY 35
#define MSG_ERR_DB_ALREADY2 36
#define MSG_ERR_NO_FILENAME 37
#define MSG_ERR_PWD_CONFIRM 38
#define MSG_FAIL 39
#define MSG_FIRST_OK 40
#define MSG_GIVE_PWD 41
#define MSG_INIT_FILE1 42
#define MSG_INIT_FILE2 43
#define MSG_INIT_FILE3 44
#define MSG_INIT_FILE4 45
#define MSG_INIT_FILE5 46
#define MSG_INIT_FILE6 47
#define MSG_INIT_FILE7 48
#define MSG_INIT_SAVE1 49
#define MSG_INIT_SAVE2 50
#define MSG_INIT_SAVE3 51
#define MSG_INIT_SAVE4 52
#define MSG_INIT_SAVE5 53
#define MSG_INIT_SAVE6 54
#define MSG_INVALID_FIELD 55
#define MSG_INVALID_ID 56
#define MSG_INV_EMAIL 57
#define MSG_INV_NICKNAME 58
#define MSG_LS1 59
#define MSG_LS2 60
#define MSG_LS3 61
#define MSG_NEWFOLD1 62
#define MSG_NEWFOLD2 63
#define MSG_NEW_HOLDER_CONFIRM_PWD 64
#define MSG_NEW_HOLDER_ERR_ALREADY 65
#define MSG_NEW_HOLDER_GIVE_PWD 66
#define MSG_NEW_HOLDER_NOT_SECRET 67
#define MSG_NEW_HOLDER_OK 68
#define MSG_NEW_SEC1 69
#define MSG_NEW_SEC2 70
#define MSG_SEC_DEL_FIELD 71
#define MSG_SHOW_HOLD1 72
#define MSG_SHOW_HOLD2 73
#define MSG_SHOW_HOLD3 74
#define MSG_SHOW_HOLD4 75
#define MSG_SHOW_HOLD5 76
#define MSG_SHSEC1 77
#define MSG_SHSEC2 78
#define MSG_SHSEC3 79
#define MSG_TRY_NOK1 80
#define MSG_TRY_NOK_ALREADY 81
#define MSG_TRY_NOK_INCONSISTENT 82
#define MSG_TRY_OK 83


extern const unsigned char msg_data[];
extern const int32_t msg_index[];
#define MSG_DATA_LEN 7296
#ifdef __cplusplus
}
#endif
