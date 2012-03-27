/*
 * ARPPing.h
 *
 *  Created on: Mar 27, 2012
 *      Author: larry
 */

#ifndef ARPPING_H_
#define ARPPING_H_

#include <string>
#include <map>
#include "Crafter.h"
#include "CrafterUtils.h"

std::map<std::string,std::string> ARPPing(const std::string& ip_net, const std::string& iface, size_t send_count);

#endif /* ARPPING_H_ */
