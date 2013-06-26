/*
Copyright (c) 2013, Gregory Detal
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the <organization> nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL ESTEBAN PELLEGRINO BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#ifndef TCPOPTIONMPTCP_H_
#define TCPOPTIONMPTCP_H_

#include "TCPOption.h"

namespace Crafter {

    class TCPOptionMPTCP: public TCPOption {

        void DefineProtocol();

        Constructor GetConstructor() const {
            return TCPOptionMPTCP::TCPOptionMPTCPConstFunc;
        };

        static Layer* TCPOptionMPTCPConstFunc() {
            return new TCPOptionMPTCP;
        };

    protected:

        void Craft();

        static const byte FieldSubtype = 2;

    public:

        enum { PROTO = 0x9006 };

        TCPOptionMPTCP();

        void SetSubtype(const word& value) {
            SetFieldValue(FieldSubtype,value);
        };

        byte GetSubtype(const word& value) {
            return GetFieldValue<word>(FieldSubtype);
        };

        ~TCPOptionMPTCP() { /* Destructor */ };

    };
    
    class TCPOptionMPTCPCapable : public TCPOptionMPTCP {

        void DefineProtocol();

        Constructor GetConstructor() const {
            return TCPOptionMPTCPCapable::TCPOptionMPTCPCapableConstFunc;
        };

        static Layer* TCPOptionMPTCPCapableConstFunc() {
            return new TCPOptionMPTCPCapable;
        };

        static const byte Version = 3;
        static const byte Checksum = 4;
        static const byte Flags = 5;
        static const byte Crypto = 6;
        static const byte SenderKey = 7;

    public:

        TCPOptionMPTCPCapable();

        enum { PROTO = 0x9007 };

        void SetVersion(const word& value) {
            SetFieldValue(Version,value);
        };

        void SetChecksum(const word& value) {
            SetFieldValue(Checksum,value);
        };

        void SetCrypto(const word& value) {
            SetFieldValue(Crypto,value);
        };

        void SetSenderKey(const uint64_t& value) {
            SetFieldValue(SenderKey,value);
        };

        void SetReceiverKey(const uint64_t& value);

        byte GetVersion() const {
            return GetFieldValue<word>(Version);
        };

        byte GetChecksum() const {
            return GetFieldValue<word>(Checksum);
        };

        uint64_t GetSenderKey() const {
            return GetFieldValue<uint64_t>(SenderKey);
        };

        uint64_t GetReceiverKey() const;

        void EnableChecksum() {
            SetChecksum(1);
        }

        void DisableChecksum() {
            SetChecksum(0);
        }

        ~TCPOptionMPTCPCapable() { /* Destructor */ };

    };

}

#endif /* TCPOPTIONMPTCP_ */
