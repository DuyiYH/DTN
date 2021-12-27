#ifndef LTPP_H_INCLUDED
#define LTPP_H_INCLUDED

#include <stdbool.h>

typedef unsigned long long	uvast;
typedef enum LocalEngineInfoType{
    LocalEngineID = 0,
    CptRexmitLimit,
	RptSegRexmitLimit,
	RecepProbLimit,
	CancelSegRexmitLimit,
	RexmitCycleLimit,
	LocalQueueProcessDelay,
	LocalOperaSchedule,
	SDAAggreSize,
	SDAAggreTime,
	//ImplementGreen
}LocalEngineInfoType;
typedef struct localInfo 
{
    unsigned int LocalEngineID;
    unsigned int CptRexmitLimit;
    unsigned int RptSegRexmitLimit;
    unsigned int RecepProbLimit;
    unsigned int CancelSegRexmitLimit;
    unsigned int RexmitCycleLimit;
    unsigned int LocalQueueProcessDelay;
	unsigned int LocalOperaSchedule;
	unsigned int SDAAggreSize;
	unsigned int SDAAggreTime;
	//unsigned int ImplementGreen;
}LocalInfo;
typedef enum RemoteEngineInfoType{
    RemoteEngineID = 0,
    UCPAddr,
	MaxSegLenth,
	OneWayLightTimeOut,
	OneWayLightTimeIn,
	RemoteQueueProcessDelay,
	RemoteOperaSchedule
}RemoteEngineInfoType;
typedef struct remoteInfo
{
    unsigned int RemoteEngineID;
    unsigned int UCPAddr;
	unsigned int MaxSegLenth;
	unsigned int OneWayLightTimeOut;
	unsigned int OneWayLightTimeIn;
	unsigned int RemoteQueueProcessDelay;
	unsigned int RemoteOperaSchedule;
	/* reserved fields
    	"Security: use authentication when sending": "hello",
    	"Security: sending authentication keys": "world",
    	"Security: require authentication on incoming sessions": "!",
    	"Security: receiving authentication keys": "hello"
	*/
	struct remoteInfo* next;
}RemoteInfo;

void localInfoSet(LocalEngineInfoType type, unsigned int value);
unsigned int getLocalInfo(LocalEngineInfoType type);
void addRemoteEngine(uvast engineID);
void deleteRemoteEngine(uvast engineID);
void RemoteInfoSet(uvast engineID, LocalEngineInfoType type, unsigned int value);
unsigned int getRemoteInfo(uvast engineID, RemoteEngineInfoType type);

typedef struct uaddr {
	char* dataPoint;
	unsigned int length;
}uaddr;
typedef struct LtpSessionId{
	uvast		sourceEngineId;
	unsigned int	sessionNbr;	/*	Assigned by source.	*/
} LtpSessionId;

LtpSessionId transmissionRequest(unsigned int destClientServiceID, uvast destLTPEngineID, 
						uaddr* clientServiceDataToSend, unsigned int lengthOfRedPart );
void cancelTransmissionRequest(LtpSessionId sessionID);
void cancelReceptionRequest(LtpSessionId sessionID);

bool SDATransmissionRequest(unsigned int clientServiceID, uvast destLTPEngineID, uaddr* clientServiceDataToSend, unsigned int lengthOfRedPart);
void onReceiveSDA(uaddr data);

typedef enum LtpCancelReasonCode{
	LtpCancelByUser = 0,
	LtpClientSvcUnreachable,
	LtpRetransmitLengthExceeded,
	LtpMiscoloredSegment,
	LtpCancelByEngine,
	LtpRetransmitTimesExceeded
} LtpCancelReasonCode;
typedef enum LtpNoticeType{
	LtpTransmissionSessionStart = 0,
	LtpReceptionSessionStart,
	LtpGreenPartSegmentArrival,
	LtpRedPartReception,
	LtpInitialTransmissionCompletion,
	LtpTransmissionSessionCompletion,
	LtpTransmissionSessionCancellation,
	LtpReceptionSessionCancellation
} LtpNoticeType;
typedef struct Notice{
	LtpNoticeType noticeType;
	LtpSessionId sessionID;

	uaddr data;
	bool EORPalsoEOB;
	unsigned int offset;
	bool EOBornot;

	LtpCancelReasonCode reasonCode;
}Notice;
Notice getNotice();

#endif