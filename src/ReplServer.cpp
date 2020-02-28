#include <iostream>
#include <exception>
#include <chrono>
#include "ReplServer.h"

const time_t secs_between_repl = 20;
const unsigned int max_servers = 10;

/*********************************************************************************************
 * ReplServer (constructor) - creates our ReplServer. Initializes:
 *
 *    verbosity - passes this value into QueueMgr and local, plus each connection
 *    _time_mult - how fast to run the simulation - 2.0 = 2x faster
 *    ip_addr - which ip address to bind the server to
 *    port - bind the server here
 *
 *********************************************************************************************/
ReplServer::ReplServer(DronePlotDB &plotdb, float time_mult)
                              :_queue(1),
                               _plotdb(plotdb),
                               _shutdown(false), 
                               _time_mult(time_mult),
                               _verbosity(1),
                               _ip_addr("127.0.0.1"),
                               _port(9999)
{
   _start_time = time(NULL);
}

ReplServer::ReplServer(DronePlotDB &plotdb, const char *ip_addr, unsigned short port, int offset, 
                        float time_mult, unsigned int verbosity)
                                 :_queue(verbosity),
                                  _plotdb(plotdb),
                                  _shutdown(false), 
                                  _time_mult(time_mult), 
                                  _verbosity(verbosity),
                                  _ip_addr(ip_addr),
                                  _port(port)

{
   _start_time = time(NULL) + offset;
}


ReplServer::~ReplServer() {
  // join all joinable daemon threads
  for (std::thread& thread : threadHandles) {
    if (thread.joinable())
      thread.join();
  }
}


/**********************************************************************************************
 * getAdjustedTime - gets the time since the replication server started up in seconds, modified
 *                   by _time_mult to speed up or slow down
 **********************************************************************************************/

time_t ReplServer::getAdjustedTime() {
   return static_cast<time_t>((time(NULL) - _start_time) * _time_mult);
}

/**********************************************************************************************
 * replicate - the main function managing replication activities. Manages the QueueMgr and reads
 *             from the queue, deconflicting entries and populating the DronePlotDB object with
 *             replicated plot points.
 *
 *    Params:  ip_addr - the local IP address to bind the listening socket
 *             port - the port to bind the listening socket
 *             
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void ReplServer::replicate(const char *ip_addr, unsigned short port) {
   _ip_addr = ip_addr;
   _port = port;
   replicate();
}

void ReplServer::replicate() {

   // Track when we started the server
   _start_time = time(NULL);
   _last_repl = 0;

   // Set up our queue's listening socket
   _queue.bindSvr(_ip_addr.c_str(), _port);
   _queue.listenSvr();

   if (_verbosity >= 2)
      std::cout << "Server bound to " << _ip_addr << ", port: " << _port << " and listening\n";

  
   // Replicate until we get the shutdown signal
   while (!_shutdown) {

      getOffsetsFromPrimaryNode(); // try to get offsets from primary node -> all other nodes

      // Check for new connections, process existing connections, and populate the queue as applicable
      _queue.handleQueue();     

      // See if it's time to replicate and, if so, go through the database, identifying new plots
      // that have not been replicated yet and adding them to the queue for replication
      if (getAdjustedTime() - _last_repl > secs_between_repl) {

         queueNewPlots();

         _last_repl = getAdjustedTime();
      }
      
      // Check the queue for updates and pop them until the queue is empty. The pop command only returns
      // incoming replication information--outgoing replication in the queue gets turned into a TCPConn
      // object and automatically removed from the queue by pop
      std::string sid;
      std::vector<uint8_t> data;
      while (_queue.pop(sid, data)) {

         // Incoming replication--add it to this server's local database
         if (data.size() != 20) // TODO: need to get rid of this magic number and find another way to identify this is an offset message
            addReplDronePlots(data);  
          else {
            if (_verbosity >= 1) std::cout << "Received new offsets from node " << sid << std::endl;
            processReceivedOffsets(data);
          }
      }       

      adjustTimeStamps(); // try to adjust timestamps to conform to primary node time
      deduplicate(); // try to remove duplicate records

      usleep(1000);
   }   
}

/**********************************************************************************************
 * queueNewPlots - looks at the database and grabs the new plots, marshalling them and
 *                 sending them to the queue manager
 *
 *    Returns: number of new plots sent to the QueueMgr
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/
unsigned int ReplServer::queueNewPlots() {
   std::vector<uint8_t> marshall_data;
   unsigned int count = 0;

   if (_verbosity >= 3)
      std::cout << "Replicating plots.\n";

   // Loop through the drone plots, looking for new ones
   std::list<DronePlot>::iterator dpit = _plotdb.begin();
   for ( ; dpit != _plotdb.end(); dpit++) {

      // If this is a new one, marshall it and clear the flag
      if (dpit->isFlagSet(DBFLAG_NEW)) {
         
         dpit->serializeWithAdjusted(marshall_data);
         dpit->clrFlags(DBFLAG_NEW);

         count++;
      }
      if (marshall_data.size() % DronePlot::getDataSizeWithAdjusted() != 0)
         throw std::runtime_error("Issue with marshalling!");

   }
  
   if (count == 0) {
      if (_verbosity >= 3)
         std::cout << "No new plots found to replicate.\n";

      return 0;
   }
 
   // Add the count onto the front
   if (_verbosity >= 3)
      std::cout << "Adding in count: " << count << "\n";

   uint8_t *ctptr_begin = (uint8_t *) &count;
   marshall_data.insert(marshall_data.begin(), ctptr_begin, ctptr_begin+sizeof(unsigned int));

   // Send to the queue manager
   if (marshall_data.size() > 0) {
      _queue.sendToAll(marshall_data);
   }

   if (_verbosity >= 2) 
      std::cout << "Queued up " << count << " plots to be replicated.\n";

   return count;
}

/**********************************************************************************************
 * addReplDronePlots - Adds drone plots to the database from data that was replicated in. 
 *                     Deconflicts issues between plot points.
 * 
 * Params:  data - should start with the number of data points in a 32 bit unsigned integer, 
 *                 then a series of drone plot points
 *
 **********************************************************************************************/

void ReplServer::addReplDronePlots(std::vector<uint8_t> &data) {
   if (data.size() < 4) {
      throw std::runtime_error("Not enough data passed into addReplDronePlots");
   }

   if ((data.size() - 4) % DronePlot::getDataSizeWithAdjusted() != 0) {
      throw std::runtime_error("Data passed into addReplDronePlots was not the right multiple of DronePlot size");
   }

   // Get the number of plot points
   unsigned int *numptr = (unsigned int *) data.data();
   unsigned int count = *numptr;

   // Store sub-vectors for efficiency
   std::vector<uint8_t> plot;
   auto dptr = data.begin() + sizeof(unsigned int);

   for (unsigned int i=0; i<count; i++) {
      plot.clear();
      plot.assign(dptr, dptr + DronePlot::getDataSizeWithAdjusted());
      addSingleDronePlot(plot);
      dptr += DronePlot::getDataSizeWithAdjusted();      
   }
   if (_verbosity >= 2)
      std::cout << "Replicated in " << count << " plots\n";   
}


/**********************************************************************************************
 * addSingleDronePlot - Takes in binary serialized drone data and adds it to the database. 
 *
 **********************************************************************************************/

void ReplServer::addSingleDronePlot(std::vector<uint8_t> &data) {
   DronePlot tmp_plot;

   tmp_plot.deserializeWithAdjusted(data);

   _plotdb.addPlotWithAdjusted(tmp_plot.drone_id, tmp_plot.node_id, tmp_plot.timestamp, tmp_plot.latitude,
                                                         tmp_plot.longitude, tmp_plot.adjusted);
}

void ReplServer::getOffsetsFromPrimaryNode() {
  if (readyToAdjust)
    return;

  auto numberOfNodes = _queue.getNumServers();

  if (offsets.size() < numberOfNodes) {
    // check for records with the same lat, long
    std::list<DronePlot>::iterator dpit;
    for (dpit = _plotdb.begin(); dpit != _plotdb.end(); dpit++) { 
      DronePlot dp = *dpit;

      auto node_id_1 = dp.node_id;
      auto latitude_1 = dp.latitude;
      auto longitude_1 = dp.longitude;
      auto time_1 = dp.timestamp;

      if (node_id_1 != primary_node_id) continue; // wait until we find an element with the primary node id

      std::list<DronePlot>::iterator dpit2;
      for (dpit2 = _plotdb.begin(); dpit2 != _plotdb.end(); dpit2++) {
        DronePlot dp2 = *dpit2;

        if (dpit2 == dpit) continue; // skip, we don't want to check an element against itself

        auto node_id_2 = dp2.node_id;
        auto latitude_2 = dp2.latitude;
        auto longitude_2 = dp2.longitude;
        auto time_2 = dp2.timestamp;
        auto adjusted_2 = dp2.adjusted;

        // if they have the same lat,long, we can derive the offset from their time difference
        if (latitude_1 == latitude_2 && longitude_1 == longitude_2 && node_id_2 != primary_node_id && !adjusted_2) {
          offsets.insert({node_id_2, (long int) time_1 - (long int) time_2});
        }
      }
    }
  } else {
    if (_verbosity >= 1) {
      std::cout << "Found all offsets!" << std::endl;
      for (auto itr = offsets.begin(); itr != offsets.end(); ++itr)
        std::cout << itr->first << '\t' << itr->second << std::endl;
    }

    sendOffsets(); // send found offsets to all other nodes so they can stop their search early :)
    // from this, other nodes will update their offsets map to mirror the one discovered 

    readyToAdjust = true;
    }
}

void ReplServer::adjustTimeStamps() {
  if (!readyToAdjust)
    return;

  for (auto itr = offsets.begin(); itr != offsets.end(); ++itr) {
    auto node_id_to_adjust = itr->first;
    auto offset = itr->second;

    std::list<DronePlot>::iterator dpit;
    for (dpit = _plotdb.begin(); dpit != _plotdb.end(); dpit++) {
        DronePlot dp = *dpit;

        auto node_id = dp.node_id;
        auto adjusted = dp.adjusted;

        if (node_id_to_adjust == node_id && !adjusted) {
          dpit->adjusted = true;
          dpit->timestamp = dpit->timestamp + offset; // adjust timestamp
        }
    }
  }
  
}

void ReplServer::deduplicate() {
  if (!readyToAdjust)
    return;

  std::list<DronePlot>::iterator dpit;
  for (dpit = _plotdb.begin(); dpit != _plotdb.end(); dpit++) {
    DronePlot dp = *dpit;

    auto latitude_1 = dp.latitude;
    auto longitude_1 = dp.longitude;
    auto time_1 = dp.timestamp;

    std::list<DronePlot>::iterator dpit2;
    for (dpit2 = _plotdb.begin(); dpit2 != _plotdb.end(); dpit2++) {
      DronePlot dp2 = *dpit2;

      if (dpit2 == dpit) continue; // skip, we don't want to check an element against itself

      auto latitude_2 = dp2.latitude;
      auto longitude_2 = dp2.longitude;
      auto time_2 = dp2.timestamp;

      if (latitude_1 == latitude_2 && longitude_1 == longitude_2 && time_1 == time_2) {
        dpit2 = _plotdb.erase(dpit2); // erase any of them; we are only keeping the first one we see
      }
    }
  }
  

}

void ReplServer::shutdown() {
   _shutdown = true;
}


void ReplServer::sendOffsets() {
  std::vector<uint8_t> marshall_data;
  unsigned int count = 0;


  for (auto itr = offsets.begin(); itr != offsets.end(); ++itr) {
    auto node_id_to_adjust = itr->first;
    auto offset = itr->second;

    serializeOffsetsMessage(marshall_data, node_id_to_adjust, offset);
    count++;
  }

   uint8_t *ctptr_begin = (uint8_t *) &count;
   marshall_data.insert(marshall_data.begin(), ctptr_begin, ctptr_begin+sizeof(unsigned int));

  // Send to the queue manager
   if (marshall_data.size() > 0) {
      _queue.sendToAll(marshall_data);
   }

   if (_verbosity >= 1) 
      std::cout << "Queued up " << count << " offsets to be distributed.\n";
}

void ReplServer::serializeOffsetsMessage(std::vector<uint8_t> &buf, int node_to_adjust, int offset) {
     uint8_t *dataptrs[2] = { (uint8_t *) &node_to_adjust,
                              (uint8_t *) &offset };

   uint8_t sizes[2] = {sizeof(node_to_adjust), sizeof(offset)};

   for (unsigned int i=0; i<2; i++) { 
      for (unsigned int j=0; j < sizes[i]; j++, dataptrs[i]++)
      {  
         buf.push_back(*dataptrs[i]);
      }
   }
}

void ReplServer::processReceivedOffsets(std::vector<uint8_t> &buf) {
   int node_to_adjust;
   int offset; 

   unsigned int *numptr = (unsigned int *) buf.data();
   unsigned int count = *numptr;

   // Store sub-vectors for efficiency
   std::vector<uint8_t> plot;
   auto dptr = buf.begin() + sizeof(unsigned int);

   auto dataSize = sizeof(node_to_adjust) + sizeof(offset);

   for (unsigned int i=0; i<count; i++) {
      plot.clear();
      plot.assign(dptr, dptr + dataSize);
      processSingleOffset(plot, node_to_adjust, offset);
      dptr += dataSize;      
   }
 }

void ReplServer::processSingleOffset(std::vector<uint8_t> &buf, int node_to_adjust, int offset) {
   uint8_t *dataptrs[2] = { (uint8_t *) &node_to_adjust,
                              (uint8_t *) &offset };

   uint8_t sizes[2] = {sizeof(node_to_adjust), sizeof(offset)};

   // Loop through all our data variables and their sizes, and read in the data
   unsigned int vpos = 0;
   for (unsigned int i=0; i<2; i++) {
      for (unsigned int j=0; j < sizes[i]; j++, dataptrs[i]++){
         if (vpos > buf.size())
            throw std::runtime_error("Offset deserialize ran out of data in vector buffer prematurely");
         *dataptrs[i] = buf[vpos++];
      }
   }

   offsets.insert({node_to_adjust, offset});
}