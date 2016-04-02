#ifndef RNPCONST_HH
#define RNPCONST_HH

#define RNP_MAX_RECORD_ADDRS 8
/// addr plus (4-byte) options 
#define RNP_OPT_LEN (4*(RNP_MAX_RECORD_ADDRS) + 4) 
#define RNP_BROADCAST_MODE 0
#define RNP_BIDIRECTIONAL 1

/// to handle debug and report macros
#ifndef STR_EXPAND
#define STR_EXPAND(tok) #tok
#endif
#ifndef STR
#define STR(tok) STR_EXPAND(tok)
#endif
/// use the built-in click chatter, or directly to stderr
#define USE_CHATTER_FOR_REPORT_RNP 1
#define USE_CHATTER_FOR_ERROR_RNP 1
#define USE_REPORT_RNP 0

#if USE_REPORT_RNP
#if USE_CHATTER_FOR_REPORT_RNP
#define RNP_REPORT(m, ...) \
{\
  click_chatter("RNP_REPORT[%s] %s " m,\
		m_myIP.unparse().c_str(),\
		Timestamp::now().unparse().c_str(), ## __VA_ARGS__);\
}
#else
#define RNP_REPORT(m, ...) \
{\
  fprintf(stderr, "RNP_REPORT[%s] %s ",\
	  m_myIP.unparse().c_str(),\
	  Timestamp::now().unparse().c_str());\
  fprintf(stderr,m, ## __VA_ARGS__);\
  fflush(stderr);\
}
#endif
#else
#define RNP_REPORT(m, ...) 
#endif

#if USE_CHATTER_FOR_ERROR_RNP
#define RNP_FATALERROR(m, ...) \
{\
  click_chatter("RNP_FATALERROR[%s] at %s - %s %d: " STR(m),\
	  m_myIP.unparse().c_str(), Timestamp::now().unparse().c_str(),\
	  __FILE__, __LINE__, ## __VA_ARGS__);\
  exit(-1);\
}
#define RNP_ERROR(m, ...) \
{\
  click_chatter("RNP_ERROR[%s] at %s - %s %d: " STR(m),\
	  m_myIP.unparse().c_str(), Timestamp::now().unparse().c_str(),\
	  __FILE__, __LINE__, ## __VA_ARGS__);\
}
#else
#define RNP_FATALERROR(m, ...) \
{\
  fprintf(stderr, "RNP_FATALERROR[%s] at %s - %s %d: ",\
	  m_myIP.unparse().c_str(), Timestamp::now().unparse().c_str(),\
	  __FILE__, __LINE__);\
  fprintf(stderr,m, ## __VA_ARGS__);\
  fflush(stderr);\
  exit(-1);\
}
#define RNP_ERROR(m, ...) \
{\
  fprintf(stderr, "RNP_ERROR[%s] at %s - %s %d: ",\
	  m_myIP.unparse().c_str(), Timestamp::now().unparse().c_str(),\
	  __FILE__, __LINE__);\
  fprintf(stderr,m, ## __VA_ARGS__);\
  fflush(stderr);\
}
#endif


#endif
