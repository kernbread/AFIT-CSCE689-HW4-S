#ifndef REPLSERVER_H
#define REPLSERVER_H

#include <map>
#include <memory>
#include <vector>
#include "QueueMgr.h"
#include "DronePlotDB.h"
#include <thread>
#include <mutex>

/***************************************************************************************
 * ReplServer - class that manages replication between servers. The data is automatically
 *              sent to the _plotdb and the replicate method loops, handling replication
 *              until _shutdown is set to true. The QueueMgr object does the majority of
 *              the communications. This object simply runs management loops and should
 *              do deconfliction of nodes
 *
 ***************************************************************************************/
class ReplServer 
{
public:
   ReplServer(DronePlotDB &plotdb, const char *ip_addr, unsigned short port, int offset,
                              float _time_mult = 1.0, unsigned int verbosity = 1);
   ReplServer(DronePlotDB &plotdb, float _time_mult = 1.0);
   virtual ~ReplServer();

   // Main replication loop, continues until _shutdown is set
   void replicate(const char *ip_addr, unsigned short port);
   void replicate();
  
   // Call this to shutdown the loop 
   void shutdown();

   // An adjusted time that accounts for "time_mult", which speeds up the clock. Any
   // attempts to check "simulator time" should use this function
   time_t getAdjustedTime();

private:

   void addReplDronePlots(std::vector<uint8_t> &data);
   void addSingleDronePlot(std::vector<uint8_t> &data);

   void getOffsetsFromPrimaryNode();
   bool readyToAdjust = false; // set to true once we have all the offsets

   void deduplicate();

   void adjustTimeStamps(); 

   unsigned int queueNewPlots();

   // holds offsets from primary node -> other nodes; key=nodeId, value=offsetFromPrimary
   std::map<int, long int> offsets;

   // holds handles to all daemon threads created
   std::vector<std::thread> threadHandles;

   QueueMgr _queue;    

   // Holds our drone plot information
   DronePlotDB &_plotdb;

   bool _shutdown;

   // How fast to run the system clock - 1.0 = normal speed, 2.0 = 2x as fast
   float _time_mult;

   // System clock time of when the server started
   time_t _start_time;

   // When the last replication happened so we can know when to do another one
   time_t _last_repl;

   // How much to spam stdout with server status
   unsigned int _verbosity;

   // Used to bind the server
   std::string _ip_addr;
   unsigned short _port;

   // primary node to get time from
   int primary_node_id = 1;

   // mutex to prevent reading/updating a data plot to the DB at the same time
   std::mutex mtx;

   // functions used to send offsets to other nodes
   void sendOffsets();
   void serializeOffsetsMessage(std::vector<uint8_t> &buf, int node_to_adjust, int offset);
   void processReceivedOffsets(std::vector<uint8_t> &buf);
   void processSingleOffset(std::vector<uint8_t> &buf, int node_to_adjust, int offset);
};


#endif
