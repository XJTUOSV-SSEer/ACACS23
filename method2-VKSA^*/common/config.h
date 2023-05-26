#ifndef SEBOX_CONFIG_H
#define SEBOX_CONFIG_H
#include <string>

#define BATCH_SIZE 100000 //useless
#define FLOW_TIMEOUT 10 //useless
#define BITMAP_SIZE 100 ////////////////////////////////bitmap长度(需要修改)

#define NN 10 //useless

#define DEC_W 1
#define DEC_U 2

const std::string mstr = "9999999999999999999999999999999999999999";

//RSA  accumulator参数
const std::string acP_1="253699952048629878783745260665553993358";
const std::string acQ_1="284802804588708767570121178795305085942";
const std::string acN = "72254457867470719938938495559676057516509089362369981914474612970086346252537";
const std::string acG = "4";
const std::string acp_1Multiacq_1 = "72254457867470719938938495559676057515970586605732643268120746530625487173236";




#endif
