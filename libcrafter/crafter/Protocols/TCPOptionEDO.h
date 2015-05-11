/*
Copyright (c) 2012, Esteban Pellegrino
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
#ifndef TCPOPTIONEDO_H_
#define TCPOPTIONEDO_H_

#include "TCPOptionLayer.h"


#ifndef TCPOPT_EDO
#define TCPOPT_EDO  237 // 0x0EDO
#endif

#ifndef TCPOPT_EDO_DEFAULT_LENGTH
#define TCPOPT_EDO_DEFAULT_LENGTH  6
#endif

#ifndef TCPOPT_EDOREQUEST_DEFAULT_LENGTH
#define TCPOPT_EDOREQUEST_DEFAULT_LENGTH  2
#endif


namespace Crafter {

    class TCPEDO: public TCPOptionLayer {

        void DefineProtocol();

        Constructor GetConstructor() const {
            return TCPEDO::TCPEDOConstFunc;
        };

        static Layer* TCPEDOConstFunc() {
            return new TCPEDO;
        };

        void Craft();

        void ParseLayerData(ParseInfo* info);

        static const byte FieldKind = 0;
        static const byte FieldLength = 1;
        static const byte FieldHeader_length = 2;

    public:

        static const word PROTO = 0x9006;

        TCPEDO();

        void SetKind(const byte& value) {
            SetFieldValue(FieldKind,value);
        };

        void SetLength(const byte& value) {
            SetFieldValue(FieldLength,value);
        };

        void SetHeader_length(const word& value) {
            SetFieldValue(FieldHeader_length,value);
        };

        byte  GetKind() const {
            return GetFieldValue<byte>(FieldKind);
        };

        byte  GetLength() const {
            return GetFieldValue<byte>(FieldLength);
        };

        word  GetHeader_length() const {
            return GetFieldValue<word>(FieldHeader_length);
        };

        ~TCPEDO() { /* Destructor */ };

        static TCPOptionLayer* Build(int subopt);

    };

     class TCPEDORequest: public TCPOptionLayer {

        void DefineProtocol();

        Constructor GetConstructor() const {
            return TCPEDORequest::TCPEDORequestConstFunc;
        };

        static Layer* TCPEDORequestConstFunc() {
            return new TCPEDORequest;
        };

        void Craft();

        //void ReDefineActiveFields();


        static const byte FieldKind = 0;
        static const byte FieldLength = 1;

    public:

        static const word PROTO = 0x9006;

        TCPEDORequest();

        void SetKind(const byte& value) {
            SetFieldValue(FieldKind,value);
        };

        void SetLength(const byte& value) {
            SetFieldValue(FieldLength,value);
        };

        byte  GetKind() const {
            return GetFieldValue<byte>(FieldKind);
        };

        byte  GetLength() const {
            return GetFieldValue<byte>(FieldLength);
        };

        ~TCPEDORequest() { /* Destructor */ };

    };

}

#endif /* TCPOPTIONEDO_H_ */
