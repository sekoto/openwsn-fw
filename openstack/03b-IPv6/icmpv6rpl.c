#include "opendefs.h"
#include "icmpv6rpl.h"
#include "icmpv6.h"
#include "openserial.h"
#include "openqueue.h"
#include "neighbors.h"
#include "packetfunctions.h"
#include "openrandom.h"
#include "scheduler.h"
#include "idmanager.h"
#include "opentimers.h"
#include "IEEE802154E.h"

//=========================== variables =======================================

//Variables of the RPLprotocol 
icmpv6rpl_vars_t            icmpv6rpl_vars;
//Variables of the Routing Table (Storing-Mode))
routes_vars_t               routes_vars;

//=========================== prototypes ======================================

// DIO-related
void icmpv6rpl_timer_DIO_cb(opentimer_id_t id);
void icmpv6rpl_timer_DIO_task(void);
void sendDIO(void);
// DAO-related
void icmpv6rpl_timer_DAO_cb(opentimer_id_t id);
void icmpv6rpl_timer_DAO_task(void);
void sendDAO(void);

// Routing table (Storing-Mode))
void registerRoute(
        open_addr_t*    routeID,
        open_addr_t*    IPv6,
        open_addr_t*    MAC64b,
        uint8_t         DAOS,
        uint8_t         PathS,  
        uint8_t         PathL
     );
bool isRoute(open_addr_t* destinadd);
uint8_t posRoute(open_addr_t* destinadd);
void removeRoute(uint8_t routeIndex);
bool ThisRowMatch(
        open_addr_t* address,
        uint8_t      rowNumber
     );
uint8_t routes_getNumRoutes(void);

void routetable_timer_cb(opentimer_id_t id);
void routetable_timer_task(void);
void routetable_read(void);

//=========================== public ==========================================

/**
\brief Initialize this module.
*/
void icmpv6rpl_init() {
   uint8_t         dodagid[16];
   uint32_t        dioPeriod;
   uint32_t        daoPeriod;
   
   // retrieve my prefix and EUI64
   memcpy(&dodagid[0],idmanager_getMyID(ADDR_PREFIX)->prefix,8); // prefix
   memcpy(&dodagid[8],idmanager_getMyID(ADDR_64B)->addr_64b,8);  // eui64
   
   //===== reset local variables
   memset(&icmpv6rpl_vars,0,sizeof(icmpv6rpl_vars_t));
   
   //=== admin
   
   icmpv6rpl_vars.busySending               = FALSE;
   icmpv6rpl_vars.fDodagidWritten           = 0;
   
   //=== DIO
   
   icmpv6rpl_vars.dio.rplinstanceId         = 0x00;        ///< TODO: put correct value
   icmpv6rpl_vars.dio.verNumb               = 0x00;        ///< TODO: put correct value
   // rank: to be populated upon TX
   icmpv6rpl_vars.dio.rplOptions            = MOP_DIO_A | \
                                              MOP_DIO_B | \
                                              MOP_DIO_C | \
                                              PRF_DIO_A | \
                                              PRF_DIO_B | \
                                              PRF_DIO_C | \
                                              G_DIO ;
   icmpv6rpl_vars.dio.DTSN                  = 0x33;        ///< TODO: put correct value
   icmpv6rpl_vars.dio.flags                 = 0x00;
   icmpv6rpl_vars.dio.reserved              = 0x00;
   memcpy(
      &(icmpv6rpl_vars.dio.DODAGID[0]),
      dodagid,
      sizeof(icmpv6rpl_vars.dio.DODAGID)
   ); // can be replaced later
   
   icmpv6rpl_vars.dioDestination.type = ADDR_128B;
   memcpy(&icmpv6rpl_vars.dioDestination.addr_128b[0],all_routers_multicast,sizeof(all_routers_multicast));
   
   icmpv6rpl_vars.dioPeriod                 = TIMER_DIO_TIMEOUT;
   dioPeriod                                = icmpv6rpl_vars.dioPeriod - 0x80 + (openrandom_get16b()&0xff);
   icmpv6rpl_vars.timerIdDIO                = opentimers_start(
                                                dioPeriod,
                                                TIMER_PERIODIC,
                                                TIME_MS,
                                                icmpv6rpl_timer_DIO_cb
                                             );
   
   //=== DAO
   
   icmpv6rpl_vars.dao.rplinstanceId         = 0x00;        ///< TODO: put correct value
   icmpv6rpl_vars.dao.K_D_flags             = FLAG_DAO_A   | \
                                              FLAG_DAO_B   | \
                                              FLAG_DAO_C   | \
                                              FLAG_DAO_D   | \
                                              FLAG_DAO_E   | \
                                              PRF_DIO_C    | \
                                              FLAG_DAO_F   | \
                                              D_DAO        |
                                              K_DAO;
   icmpv6rpl_vars.dao.reserved              = 0x00;
   icmpv6rpl_vars.dao.DAOSequence           = 0x00;
   memcpy(
      &(icmpv6rpl_vars.dao.DODAGID[0]),
      dodagid,
      sizeof(icmpv6rpl_vars.dao.DODAGID)
   );  // can be replaced later
   
   icmpv6rpl_vars.dao_transit.type          = OPTION_TRANSIT_INFORMATION_TYPE;
   // optionLength: to be populated upon TX
   icmpv6rpl_vars.dao_transit.E_flags       = E_DAO_Transit_Info;
   icmpv6rpl_vars.dao_transit.PathControl   = PC1_A_DAO_Transit_Info | \
                                              PC1_B_DAO_Transit_Info | \
                                              PC2_A_DAO_Transit_Info | \
                                              PC2_B_DAO_Transit_Info | \
                                              PC3_A_DAO_Transit_Info | \
                                              PC3_B_DAO_Transit_Info | \
                                              PC4_A_DAO_Transit_Info | \
                                              PC4_B_DAO_Transit_Info;  
   icmpv6rpl_vars.dao_transit.PathSequence  = 0x00; // to be incremented at each TX
   icmpv6rpl_vars.dao_transit.PathLifetime  = 0xAA;
   //target information
   icmpv6rpl_vars.dao_target.type  = OPTION_TARGET_INFORMATION_TYPE;
   icmpv6rpl_vars.dao_target.optionLength  = 0;
   icmpv6rpl_vars.dao_target.flags  = 0;
   icmpv6rpl_vars.dao_target.prefixLength = 0;
   
   icmpv6rpl_vars.daoPeriod                 = TIMER_DAO_TIMEOUT;
   daoPeriod                                = icmpv6rpl_vars.daoPeriod - 0x80 + (openrandom_get16b()&0xff);
   icmpv6rpl_vars.timerIdDAO                = opentimers_start(
                                                daoPeriod,
                                                TIMER_PERIODIC,
                                                TIME_MS,
                                                icmpv6rpl_timer_DAO_cb
                                             );
   
}

void routingtable_init() {    
   uint32_t        RTPeriod;
   
   // clear module variables
   memset(&routes_vars,0,sizeof(routes_vars_t));
   
   routes_vars.RTPeriod                 = TIMER_RT_TIMEOUT;
   RTPeriod                             = routes_vars.RTPeriod - 0x80 + (openrandom_get16b()&0xff);
   routes_vars.timerIdRT                = opentimers_start(
                                                RTPeriod,
                                                TIMER_PERIODIC,
                                                TIME_MS,
                                                routetable_timer_cb
                                          );
}

void  icmpv6rpl_writeDODAGid(uint8_t* dodagid) {
   
   // write DODAGID to DIO/DAO
   memcpy(
      &(icmpv6rpl_vars.dio.DODAGID[0]),
      dodagid,
      sizeof(icmpv6rpl_vars.dio.DODAGID)
   );
   memcpy(
      &(icmpv6rpl_vars.dao.DODAGID[0]),
      dodagid,
      sizeof(icmpv6rpl_vars.dao.DODAGID)
   );
   
   // remember I got a DODAGID
   icmpv6rpl_vars.fDodagidWritten = 1;
}

uint8_t icmpv6rpl_getRPLIntanceID(){
   return icmpv6rpl_vars.dao.rplinstanceId;
}
                                                
void    icmpv6rpl_getRPLDODAGid(uint8_t* address_128b){
    memcpy(address_128b,icmpv6rpl_vars.dao.DODAGID,16);
}

/**
\brief Called when DIO/DAO was sent.

\param[in] msg   Pointer to the message just sent.
\param[in] error Outcome of the sending.
*/
void icmpv6rpl_sendDone(OpenQueueEntry_t* msg, owerror_t error) {
   
   // take ownership over that packet
   msg->owner = COMPONENT_ICMPv6RPL;
   
   // make sure I created it
   if (msg->creator!=COMPONENT_ICMPv6RPL) {
      openserial_printError(COMPONENT_ICMPv6RPL,ERR_UNEXPECTED_SENDDONE,
                            (errorparameter_t)0,
                            (errorparameter_t)0);
   }
   
   // free packet
   openqueue_freePacketBuffer(msg);
   
   // I'm not busy sending anymore
   icmpv6rpl_vars.busySending = FALSE;
}

/**
\brief Called when RPL message received.

\param[in] msg   Pointer to the received message.
*/
void icmpv6rpl_receive(OpenQueueEntry_t* msg) {
   uint8_t          icmpv6code;
   open_addr_t      myPrefix;
   //uint8_t          i;
   uint8_t          daooptioncode;
   uint8_t          posi;
   uint8_t*         pposi;
   open_addr_t      routeadd;
   open_addr_t      origipv6;
   open_addr_t      origmac;
   open_addr_t      origpref;

   // take ownership
   msg->owner      = COMPONENT_ICMPv6RPL;
   
   // retrieve ICMPv6 code
   icmpv6code      = (((ICMPv6_ht*)(msg->payload))->code);
   
   //printf ("\n");

   // retrieve ID of the MOTE
   //printf("### ID-MOTE -- ");
   //for (i=0;i<LENGTH_ADDR64b;i++) {
   //     printf(" %X",(&idmanager_vars.my64bID)->addr_64b[i]);  
   //}
   //printf ("\n");
   
   // toss ICMPv6 header
   packetfunctions_tossHeader(msg,sizeof(ICMPv6_ht));
   
   // IPv6 destination
   //printf("### MSG-Destination-IPv6 -- ");
   //for (i=0;i<LENGTH_ADDR128b;i++) {
   //     printf (" %X",msg->l3_destinationAdd.addr_128b[i]);  
   //}
   //printf ("\n");
   
   // handle message
   switch (icmpv6code) {
      case IANA_ICMPv6_RPL_DIS:
         //printf("+++++ DIS-Message \n");
         icmpv6rpl_timer_DIO_task();
         break;
      case IANA_ICMPv6_RPL_DIO:
         //printf("+++++ DIO-Message \n");
         if (idmanager_getIsDAGroot()==TRUE) {
            // stop here if I'm in the DAG root
            break; // break, don't return
         }
         
         // update neighbor table
         neighbors_indicateRxDIO(msg);
         
         memcpy(
            &(icmpv6rpl_vars.dio),
            (icmpv6rpl_dio_ht*)(msg->payload),
            sizeof(icmpv6rpl_dio_ht)
         );
         
         // write DODAGID in DIO and DAO
         icmpv6rpl_writeDODAGid(&(((icmpv6rpl_dio_ht*)(msg->payload))->DODAGID[0]));
         
         // update my prefix
         myPrefix.type = ADDR_PREFIX;
         memcpy(
            myPrefix.prefix,
            &((icmpv6rpl_dio_ht*)(msg->payload))->DODAGID[0],
            sizeof(myPrefix.prefix)
         );
         idmanager_setMyID(&myPrefix);
                  
         break;
      
      case IANA_ICMPv6_RPL_DAO:
        //printf("+++++ DAO-Message \n");
       	if (RPLMODE==0){ 
		
            // this should never happen
            //openserial_printCritical(COMPONENT_ICMPv6RPL,ERR_UNEXPECTED_DAO,
            //                      (errorparameter_t)0,
            //                      (errorparameter_t)0);
		
	} else if (RPLMODE==1){ 
		
            memcpy(
                &(icmpv6rpl_vars.dao),
		(icmpv6rpl_dao_ht*)(msg->payload),
		sizeof(icmpv6rpl_dao_ht)
            );
			
            //printf ("/////////////////////////////////////////\n");
            //printf ("--SRC-Add.. ");
			
            //memcpy(&origipv6.addr_128b,&(msg->l3_sourceAdd.addr_128b),sizeof(msg->l3_sourceAdd.addr_128b));
            memcpy(&origipv6,&(msg->l3_sourceAdd),sizeof(msg->l3_sourceAdd));
			
            packetfunctions_ip128bToMac64b(&origipv6,&origpref,&origmac);
            //for (i=LENGTH_ADDR64b;i<LENGTH_ADDR128b;i++) {
            //		origmac.addr_64b[i-8] = origipv6.addr_128b[i];
            //}
			
            //for (i=0;i<LENGTH_ADDR128b;i++) {
           //     //printf (" %X",msg->l3_sourceAdd.addr_128b[i]);  
           //     printf (" %X",origipv6.addr_128b[i]);
           // }
           // printf ("\n");
	
            //printf ("--SRC-MAC64.. ");
            //for (i=0;i<LENGTH_ADDR64b;i++) {
            //    printf (" %X",origmac.addr_64b[i]);
            //}
            //printf ("\n");
			
            //printf ("-- Payload.. ");
            //for (i=0;i<120;i++) {
            //    printf (" %X",msg->payload[i]);  
            //}
            //printf ("\n");
			
            // retrieve DAO option code
            daooptioncode      = msg->payload[sizeof(icmpv6rpl_dao_ht)];
            //printf (" -daooptioncode-- %i \n",daooptioncode);
			
            posi=sizeof(icmpv6rpl_dao_ht);
            pposi = &(msg->payload[posi]);
			
            while(posi > 0){
				
                // retrieve DAO option code
                daooptioncode = msg->payload[posi];   
                //printf ("--daooptioncode.. %i \n",daooptioncode);
				
                // DAO option select
                switch (daooptioncode) {
			
                    case OPTION_TARGET_INFORMATION_TYPE:    
					
                        //printf ("##### Target Option \n");
                        //printf ("** type %X \n",((icmpv6rpl_dao_target_ht*)(pposi))->type);
                        //printf ("** OptionLength %X \n",((icmpv6rpl_dao_target_ht*)(pposi))->optionLength);
                        //printf ("** Flags %X \n",((icmpv6rpl_dao_target_ht*)(pposi))->flags);
                        //printf ("** PrefixLength %X \n",((icmpv6rpl_dao_target_ht*)(pposi))->prefixLength);
                        //**
					
                        memcpy(
                            &(icmpv6rpl_vars.dao_target),
                            (icmpv6rpl_dao_target_ht*)(pposi),
                            sizeof(icmpv6rpl_dao_target_ht)
                        );
                        //printf ("** PrefixLength %X \n",(&icmpv6rpl_vars.dao_target)->prefixLength);

                        posi=posi+sizeof(icmpv6rpl_dao_target_ht)-1; 
                        pposi = &(msg->payload[posi]);
					
                        memcpy(&routeadd,(open_addr_t*)(pposi),sizeof(open_addr_t));
                        // Record the IPv6 anounced
                        //for (i=0;i<LENGTH_ADDR128b;i++) {
                        //	routeadd.addr_128b[i] = ((open_addr_t*)(pposi))->addr_128b[i];
                        //}
                        routeadd.type=ADDR_128B;
                        origipv6.type=ADDR_128B;
                        origmac.type=ADDR_64B;
                                                
                        //printf ("** Child-Address.. ");
                        //for (i=0;i<LENGTH_ADDR128b;i++) {
                        //    printf (" %X",routeadd.addr_128b[i]);  
                        //}
                        //printf ("\n");
					
                        //printf ("...Before Register .. %X\n",routes_getNumRoutes()); 
                        registerRoute(&routeadd,&origipv6,&origmac,(&icmpv6rpl_vars.dao)->DAOSequence,(&icmpv6rpl_vars.dao_transit)->PathSequence,(&icmpv6rpl_vars.dao_transit)->PathLifetime);
                        //printf ("...After Register .. %X\n",routes_getNumRoutes());
					
                        posi=posi+LENGTH_ADDR128b+1; 
                        pposi = &(msg->payload[posi]);
				
                        // printf ("** Next Byte %X \n",msg->payload[posi]);
				
                        break;
				
                    case OPTION_TRANSIT_INFORMATION_TYPE:    
                        //printf ("##### Transit Option \n");
                        //printf ("** type %X \n",((icmpv6rpl_dao_transit_ht*)(pposi))->type);
                        //printf ("** optionLength %X \n",((icmpv6rpl_dao_transit_ht*)(pposi))->optionLength);
                        //printf ("** E_flags %X \n",((icmpv6rpl_dao_transit_ht*)(pposi))->E_flags);
                        //printf ("** PathControl %X \n",((icmpv6rpl_dao_transit_ht*)(pposi))->PathControl);
                        //printf ("** PathSequence %X \n",((icmpv6rpl_dao_transit_ht*)(pposi))->PathSequence);
                        //printf ("** PathLifetime %X \n",((icmpv6rpl_dao_transit_ht*)(pposi))->PathLifetime);
					
                        memcpy(
                            &(icmpv6rpl_vars.dao_transit),
                            (icmpv6rpl_dao_transit_ht*)(pposi),
                            sizeof(icmpv6rpl_dao_transit_ht)
                        );
				
                        //printf ("** type %X \n",(&icmpv6rpl_vars.dao_transit)->type);
                        //printf ("** optionLength %X \n",(&icmpv6rpl_vars.dao_transit)->optionLength);
                        //printf ("** E_flags %X \n",(&icmpv6rpl_vars.dao_transit)->E_flags);
                        //printf ("** PathControl %X \n",(&icmpv6rpl_vars.dao_transit)->PathControl);
                        //printf ("** PathSequence %X \n",(&icmpv6rpl_vars.dao_transit)->PathSequence);
                        //printf ("** PathLifetime %X \n",(&icmpv6rpl_vars.dao_transit)->PathLifetime);
					
                        posi=posi+sizeof(icmpv6rpl_dao_transit_ht)-1; 
                        pposi = &(msg->payload[posi]);
				
                        //if ((((icmpv6rpl_dao_transit_ht*)(pposi))->optionLength)==0){
                        //     printf ("** Storing-Mode.. (No Parent Address)\n");   
                        //}else{
                        //    printf ("** Parent-Address  ");
                        //    for (i=0;i<LENGTH_ADDR128b;i++) {
                        //        printf (" %X",((open_addr_t*)(pposi))->addr_128b[i]);  
                        //    }
                        //    printf ("\n");
                        //}
	
                        posi=posi+LENGTH_ADDR128b+1; 
                        pposi = &(msg->payload[posi]);
				
                        //printf ("** Next Byte %X \n",msg->payload[posi]);
	
                        break;
				
                    default:  
                        //printf ("##### END DAO %X \n",msg->payload[posi]);
                        posi=0;
                        break;
				
                }
			
            }
			
			
        }

         break;
         
      default:
         // this should never happen
         openserial_printError(COMPONENT_ICMPv6RPL,ERR_MSG_UNKNOWN_TYPE,
                               (errorparameter_t)icmpv6code,
                               (errorparameter_t)0);
         break;
      
   }
   
   // free message
   openqueue_freePacketBuffer(msg);
}

//=========================== private =========================================

//===== DIO-related

/**
\brief DIO timer callback function.

\note This function is executed in interrupt context, and should only push a 
   task.
*/
void icmpv6rpl_timer_DIO_cb(opentimer_id_t id) {
   scheduler_push_task(icmpv6rpl_timer_DIO_task,TASKPRIO_RPL);
}

/**
\brief Handler for DIO timer event.

\note This function is executed in task context, called by the scheduler.
*/
void icmpv6rpl_timer_DIO_task() {
   uint32_t        dioPeriod;
   // send DIO
   sendDIO();
   
   // arm the DIO timer with this new value
   dioPeriod = icmpv6rpl_vars.dioPeriod - 0x80 + (openrandom_get16b()&0xff);
   opentimers_setPeriod(
      icmpv6rpl_vars.timerIdDIO,
      TIME_MS,
      dioPeriod
   );
}

/**
\brief Prepare and a send a RPL DIO.
*/
void sendDIO() {
   OpenQueueEntry_t*    msg;
   
   // stop if I'm not sync'ed
   if (ieee154e_isSynch()==FALSE) {
      
      // remove packets genereted by this module (DIO and DAO) from openqueue
      openqueue_removeAllCreatedBy(COMPONENT_ICMPv6RPL);
      
      // I'm not busy sending a DIO/DAO
      icmpv6rpl_vars.busySending  = FALSE;
      
      // stop here
      return;
   }
   
   // do not send DIO if I have the default DAG rank
   if (neighbors_getMyDAGrank()==DEFAULTDAGRANK) {
      return;
   }
   
   // do not send DIO if I'm already busy sending
   if (icmpv6rpl_vars.busySending==TRUE) {
      return;
   }
   
   // if you get here, all good to send a DIO
   
   // I'm now busy sending
   icmpv6rpl_vars.busySending = TRUE;
   
   // reserve a free packet buffer for DIO
   msg = openqueue_getFreePacketBuffer(COMPONENT_ICMPv6RPL);
   if (msg==NULL) {
      openserial_printError(COMPONENT_ICMPv6RPL,ERR_NO_FREE_PACKET_BUFFER,
                            (errorparameter_t)0,
                            (errorparameter_t)0);
      icmpv6rpl_vars.busySending = FALSE;
      
      return;
   }
   
   // take ownership
   msg->creator                             = COMPONENT_ICMPv6RPL;
   msg->owner                               = COMPONENT_ICMPv6RPL;
   
   // set transport information
   msg->l4_protocol                         = IANA_ICMPv6;
   msg->l4_sourcePortORicmpv6Type           = IANA_ICMPv6_RPL;
   
   // set DIO destination
   memcpy(&(msg->l3_destinationAdd),&icmpv6rpl_vars.dioDestination,sizeof(open_addr_t));
   
   //===== DIO payload
   // note: DIO is already mostly populated
   icmpv6rpl_vars.dio.rank                  = neighbors_getMyDAGrank();
   packetfunctions_reserveHeaderSize(msg,sizeof(icmpv6rpl_dio_ht));
   memcpy(
      ((icmpv6rpl_dio_ht*)(msg->payload)),
      &(icmpv6rpl_vars.dio),
      sizeof(icmpv6rpl_dio_ht)
   );
   
   // reverse the rank bytes order in Big Endian
   *(msg->payload+2) = (icmpv6rpl_vars.dio.rank >> 8) & 0xFF;
   *(msg->payload+3) = icmpv6rpl_vars.dio.rank        & 0xFF;
   
   //===== ICMPv6 header
   packetfunctions_reserveHeaderSize(msg,sizeof(ICMPv6_ht));
   ((ICMPv6_ht*)(msg->payload))->type       = msg->l4_sourcePortORicmpv6Type;
   ((ICMPv6_ht*)(msg->payload))->code       = IANA_ICMPv6_RPL_DIO;
   packetfunctions_calculateChecksum(msg,(uint8_t*)&(((ICMPv6_ht*)(msg->payload))->checksum));//call last
   
   //send
   if (icmpv6_send(msg)!=E_SUCCESS) {
      icmpv6rpl_vars.busySending = FALSE;
      openqueue_freePacketBuffer(msg);
   } else {
      icmpv6rpl_vars.busySending = FALSE; 
   }
}

//===== DAO-related

/**
\brief DAO timer callback function.

\note This function is executed in interrupt context, and should only push a
   task.
*/
void icmpv6rpl_timer_DAO_cb(opentimer_id_t id) {
   scheduler_push_task(icmpv6rpl_timer_DAO_task,TASKPRIO_RPL);
}

/**
\brief Handler for DAO timer event.

\note This function is executed in task context, called by the scheduler.
*/
void icmpv6rpl_timer_DAO_task() {
   uint32_t        daoPeriod;
   
   // send DAO
   sendDAO();
   
   // arm the DAO timer with this new value
   daoPeriod = icmpv6rpl_vars.daoPeriod - 0x80 + (openrandom_get16b()&0xff);
   opentimers_setPeriod(
      icmpv6rpl_vars.timerIdDAO,
      TIME_MS,
      daoPeriod
   );
}

/**
\brief Prepare and a send a RPL DAO.
*/
void sendDAO() {
   OpenQueueEntry_t*    msg;                // pointer to DAO messages
   uint8_t              nbrIdx;             // running neighbor index
   uint8_t              numTransitParents,numTargetParents;  // the number of parents indicated in transit option
   open_addr_t          address;
   open_addr_t*         prefix;
   uint8_t              i;
   open_addr_t          rtpref;
   open_addr_t          rtadd;
   int16_t              ccount;
   uint8_t              posi;
   bool                 selected;
   bool                 onetarget;
   
   if (ieee154e_isSynch()==FALSE) {
      // I'm not sync'ed 
      
      // delete packets genereted by this module (DIO and DAO) from openqueue
      openqueue_removeAllCreatedBy(COMPONENT_ICMPv6RPL);
      
      // I'm not busy sending a DIO/DAO
      icmpv6rpl_vars.busySending = FALSE;
      
      // stop here
      return;
   }
   
   // dont' send a DAO if you're the DAG root
   if (idmanager_getIsDAGroot()==TRUE) {
      return;
   }
   
   // dont' send a DAO if you did not acquire a DAGrank
   if (neighbors_getMyDAGrank()==DEFAULTDAGRANK) {
       return;
   }
   
   // dont' send a DAO if you're still busy sending the previous one
   if (icmpv6rpl_vars.busySending==TRUE) {
      return;
   }
   
   // if you get here, you start construct DAO
   
   // reserve a free packet buffer for DAO
   msg = openqueue_getFreePacketBuffer(COMPONENT_ICMPv6RPL);
   if (msg==NULL) {
      openserial_printError(COMPONENT_ICMPv6RPL,ERR_NO_FREE_PACKET_BUFFER,
                            (errorparameter_t)0,
                            (errorparameter_t)0);
      return;
   }
   
   // take ownership
   msg->creator                             = COMPONENT_ICMPv6RPL;
   msg->owner                               = COMPONENT_ICMPv6RPL;
   
   // set transport information
   msg->l4_protocol                         = IANA_ICMPv6;
   msg->l4_sourcePortORicmpv6Type           = IANA_ICMPv6_RPL;
   
   // set DAO destination
   msg->l3_destinationAdd.type=ADDR_128B;
   
   if (RPLMODE==0){ 
		memcpy(msg->l3_destinationAdd.addr_128b,icmpv6rpl_vars.dio.DODAGID,sizeof(icmpv6rpl_vars.dio.DODAGID));
   } else if (RPLMODE==1){ 
		// l3_destinationAdd MUST be Prefered Parent in Storing mode
		neighbors_getPreferredParentEui64(&address);
		packetfunctions_mac64bToIp128b(idmanager_getMyID(ADDR_PREFIX),&address,&(msg->l3_destinationAdd));
   }
   
   //===== fill in packet
   
   // TARGET OPTION
   //target information is required. RFC 6550 page 55.
   /*
   One or more Transit Information options MUST be preceded by one or
   more RPL Target options.   
   */
   
   //printf ("\n");
   //printf("### Mounting DAO-Target-Option -- \n");
   // Limit onlye one Target Option
   onetarget=FALSE;
   
   if ( ( RPLMODE == 1 ) || ( routes_vars.tosend == TRUE ) ){ 
       
        // Routes announced -- Storing-Mode
        //Predefined values for controlling send
        ccount=65535;
        posi=0;
        selected=FALSE;
   
        //printf("### ID-MOTE -- ");
        //for (i=0;i<LENGTH_ADDR64b;i++) {
        //    printf(" %X",(&idmanager_vars.my64bID)->addr_64b[i]);  
        //}
        //printf ("\n");
   
        for (nbrIdx=0;nbrIdx<MAX_ROUTE_NUM;nbrIdx++) {
            if (routes_vars.routes[nbrIdx].used==TRUE) {
                
                if ( (routes_vars.routes[nbrIdx].tosend==TRUE) || (ccount > routes_vars.routes[nbrIdx].scount) ) {
                    selected=TRUE; 
                    posi=nbrIdx;
                    ccount=routes_vars.routes[nbrIdx].scount;
                }    
                
                //printf ("+++ Type IPv6 registered - %u\n",routes_vars.routes[nbrIdx].destination.type);
                //printf ("|-----Route(%u)------\n",nbrIdx);
                //printf("|### Routing-IPv6-Destiny(Child) -- ");
                //for (i=0;i<LENGTH_ADDR128b;i++) {
                //    printf (" %X",routes_vars.routes[nbrIdx].destination.addr_128b[i]);  
                //}
                //printf ("\n"); 
                //printf("|### Routing-IPv6-Publisher -- ");
                //for (i=0;i<LENGTH_ADDR128b;i++) {
                //    printf (" %X",routes_vars.routes[nbrIdx].addr_128b.addr_128b[i]);  
                //}
                //printf ("\n"); 
                //printf ("|-------------------\n");
                //
                //printf ("...Vuelta\n");
            }
            
        }
            
        if ( selected == TRUE ){
            onetarget=TRUE;
            routes_vars.tosend=FALSE;
            routes_vars.routes[posi].scount=routes_vars.routes[posi].scount+1;
            
            packetfunctions_ip128bToMac64b(&(routes_vars.routes[posi].destination),&rtpref,&rtadd);
            packetfunctions_writeAddress(msg,&rtadd,OW_BIG_ENDIAN);
            packetfunctions_writeAddress(msg,&rtpref,OW_BIG_ENDIAN);
            // target info fields 
            icmpv6rpl_vars.dao_target.optionLength  = LENGTH_ADDR128b +sizeof(icmpv6rpl_dao_target_ht) - 2; //no header type and length
            icmpv6rpl_vars.dao_target.type  = OPTION_TARGET_INFORMATION_TYPE;
            icmpv6rpl_vars.dao_target.flags  = 0;       //must be 0
            icmpv6rpl_vars.dao_target.prefixLength = 128; //128 leading bits  -- full address.
            // write target info in packet
            packetfunctions_reserveHeaderSize(msg,sizeof(icmpv6rpl_dao_target_ht));
            memcpy(
                ((icmpv6rpl_dao_target_ht*)(msg->payload)),
                &(icmpv6rpl_vars.dao_target),
                sizeof(icmpv6rpl_dao_target_ht)
            );
        }

   }
   
   if ( onetarget == FALSE ){
        // Direct Child of the MOTE
        numTargetParents                        = 0;
        for (nbrIdx=0;nbrIdx<MAXNUMNEIGHBORS;nbrIdx++) {
            if ((neighbors_isNeighborWithHigherDAGrank(nbrIdx))==TRUE) {
                // this neighbor is of higher DAGrank as I am. so it is my child
                //printf("*** Writing Target Address -- OW_BIG_ENDIAN ");
                // write it's address in DAO RFC6550 page 80 check point 1.
                neighbors_getNeighbor(&address,ADDR_64B,nbrIdx); 
                packetfunctions_writeAddress(msg,&address,OW_BIG_ENDIAN);
                prefix=idmanager_getMyID(ADDR_PREFIX);
                packetfunctions_writeAddress(msg,prefix,OW_BIG_ENDIAN);
        
                // update target info fields 
                // from rfc6550 p.55 -- Variable, length of the option in octets excluding the Type and Length fields.
                // poipoi xv: assuming that type and length fields refer to the 2 first bytes of the header
                icmpv6rpl_vars.dao_target.optionLength  = LENGTH_ADDR128b +sizeof(icmpv6rpl_dao_target_ht) - 2; //no header type and length
                icmpv6rpl_vars.dao_target.type  = OPTION_TARGET_INFORMATION_TYPE;
                icmpv6rpl_vars.dao_target.flags  = 0;       //must be 0
                icmpv6rpl_vars.dao_target.prefixLength = 128; //128 leading bits  -- full address.
         
                // write transit info in packet
                packetfunctions_reserveHeaderSize(msg,sizeof(icmpv6rpl_dao_target_ht));
                memcpy(
                    ((icmpv6rpl_dao_target_ht*)(msg->payload)),
                    &(icmpv6rpl_vars.dao_target),
                    sizeof(icmpv6rpl_dao_target_ht)
                );
                //printf ("...Target Real\n");
                // remember I found it
                numTargetParents++;
            }  
            //limit to MAX_TARGET_PARENTS the number of DAO target addresses to send
            //section 8.2.1 pag 67 RFC6550 -- using a subset
            // poipoi TODO base selection on ETX rather than first X.
            if (numTargetParents>=MAX_TARGET_PARENTS) break;
        }
        onetarget=TRUE;
        routes_vars.tosend=TRUE;
   }
    
   // TRANSIT OPTION
   //NOTE: limit to preferrred parent only the number of DAO transit addresses to send
   
   //=== transit option -- from RFC 6550, page 55 - 1 transit information header per parent is required. 
   //getting only preferred parent as transit
   numTransitParents=0;
   
   if (RPLMODE==0){ 
		neighbors_getPreferredParentEui64(&address);
		packetfunctions_writeAddress(msg,&address,OW_BIG_ENDIAN);
		prefix=idmanager_getMyID(ADDR_PREFIX);
		packetfunctions_writeAddress(msg,prefix,OW_BIG_ENDIAN);
   } else if (RPLMODE==1){ 
		// Parent Address in storing-mode is unassigned
		// Unassigned bits of the Transit Information option are reserved.  
		// They MUST be set to zero on transmission and MUST be ignored on reception.
		for (i=0;i<LENGTH_ADDR128b;i++) {
                    msg->payload      -= sizeof(uint8_t);
                    msg->length       += sizeof(uint8_t);
                    *((uint8_t*)(msg->payload)) = 0;
		}
   }

   // update transit info fields
   // from rfc6550 p.55 -- Variable, depending on whether or not the DODAG ParentAddress subfield is present.
   // poipoi xv: it is not very clear if this includes all fields in the header. or as target info 2 bytes are removed.
   // using the same pattern as in target information.
   
   if (RPLMODE==0){ 
		icmpv6rpl_vars.dao_transit.optionLength  = LENGTH_ADDR128b + sizeof(icmpv6rpl_dao_transit_ht)-2;
   } else if (RPLMODE==1){ 
		// optionLength set to 0 because Storing-mode
		icmpv6rpl_vars.dao_transit.optionLength  = 0;
   }

   icmpv6rpl_vars.dao_transit.PathControl=0; //todo. this is to set the preference of this parent.      
   icmpv6rpl_vars.dao_transit.type=OPTION_TRANSIT_INFORMATION_TYPE;
           
   // write transit info in packet
   packetfunctions_reserveHeaderSize(msg,sizeof(icmpv6rpl_dao_transit_ht));
   memcpy(
          ((icmpv6rpl_dao_transit_ht*)(msg->payload)),
          &(icmpv6rpl_vars.dao_transit),
          sizeof(icmpv6rpl_dao_transit_ht)
   );
   numTransitParents++;
   
   // stop here if no parents found
   if (numTransitParents==0) {
      openqueue_freePacketBuffer(msg);
      return;
   }
   
   icmpv6rpl_vars.dao_transit.PathSequence++; //increment path sequence.
   // if you get here, you will send a DAO
   
   
   //=== DAO header
   packetfunctions_reserveHeaderSize(msg,sizeof(icmpv6rpl_dao_ht));
   memcpy(
      ((icmpv6rpl_dao_ht*)(msg->payload)),
      &(icmpv6rpl_vars.dao),
      sizeof(icmpv6rpl_dao_ht)
   );
   
   //printf ("...Mounting DAO ICMPv6 header\n");
   //=== ICMPv6 header
   packetfunctions_reserveHeaderSize(msg,sizeof(ICMPv6_ht));
   ((ICMPv6_ht*)(msg->payload))->type       = msg->l4_sourcePortORicmpv6Type;
   ((ICMPv6_ht*)(msg->payload))->code       = IANA_ICMPv6_RPL_DAO;
   packetfunctions_calculateChecksum(msg,(uint8_t*)&(((ICMPv6_ht*)(msg->payload))->checksum)); //call last
   
   //printf ("...Sending DAO\n");
   //===== send
   if (icmpv6_send(msg)==E_SUCCESS) {
      icmpv6rpl_vars.busySending = TRUE;
   } else {
      openqueue_freePacketBuffer(msg);
   }
   //printf ("...Sended DAO\n");
}

void icmpv6rpl_setDIOPeriod(uint16_t dioPeriod){
   uint32_t        dioPeriodRandom;
   
   icmpv6rpl_vars.dioPeriod = dioPeriod;
   dioPeriodRandom = icmpv6rpl_vars.dioPeriod - 0x80 + (openrandom_get16b()&0xff);
   opentimers_setPeriod(
       icmpv6rpl_vars.timerIdDIO,
       TIME_MS,
       dioPeriodRandom
   );
}

void icmpv6rpl_setDAOPeriod(uint16_t daoPeriod){
   uint32_t        daoPeriodRandom;
   
   icmpv6rpl_vars.daoPeriod = daoPeriod;
   daoPeriodRandom = icmpv6rpl_vars.daoPeriod - 0x80 + (openrandom_get16b()&0xff);
   opentimers_setPeriod(
       icmpv6rpl_vars.timerIdDAO,
       TIME_MS,
       daoPeriodRandom
   );
}

// Routing Table related
void registerRoute(open_addr_t*     destaddress,
                   open_addr_t*     IPv6,
                   open_addr_t*     MAC64b,
                   uint8_t          DAOS,
                   uint8_t          PathS,
                   uint8_t          PathL) {
   uint8_t  i,posi;

   //printf("Registering route process....\n");
   // printf("IPv6 type....%u\n",IPv6->type); 
   // add this Route
   if (isRoute(destaddress)==FALSE) {
      //printf("The route is not on the table...\n");
      i=0;
      while(i<MAX_ROUTE_NUM) {
         if (routes_vars.routes[i].used==FALSE) {
             //printf("Adding route...\n");
            // add this route
            routes_vars.routes[i].used                      = TRUE;
            routes_vars.routes[i].advertneighinf            = 0;
            memcpy(&routes_vars.routes[i].addr_128b,IPv6,sizeof(open_addr_t));
            (&routes_vars.routes[i].addr_128b)->type=ADDR_128B;
            memcpy(&routes_vars.routes[i].addr_64b,MAC64b,sizeof(open_addr_t));
            (&routes_vars.routes[i].addr_64b)->type=ADDR_64B;
            routes_vars.routes[i].retcount                  = 0;
            routes_vars.routes[i].DAOSequence               = DAOS;
            routes_vars.routes[i].PathSequence              = PathS;
            routes_vars.routes[i].PathLifetime              = PathL;
            memcpy(&routes_vars.routes[i].destination,destaddress,sizeof(open_addr_t));
            (&routes_vars.routes[i].destination)->type=ADDR_128B;
            routes_vars.routes[i].tosend                    = TRUE;
            routes_vars.routes[i].scount                    = 0;

            break;
         }
         i++;
      }
      if (i==MAX_ROUTE_NUM) {
         //openserial_printError(COMPONENT_NEIGHBORS,ERR_NEIGHBORS_FULL,
         //                      (errorparameter_t)MAX_ROUTE_NUM,
         //                      (errorparameter_t)0);
         return;
      }
   }else{
       //printf("The route is in the table already...\n");
        // Obtain position of route
        posi = posRoute(destaddress);
        // Is new the address of publisher

        // In case of error and no position is bigger than MAX_ROUTE_NUM
        if (posi <= MAX_ROUTE_NUM){
            // Looking for update in the info of routing, in case of new info updates route
            if ((routes_vars.routes[posi].DAOSequence != DAOS) || (routes_vars.routes[posi].PathSequence != PathS) || !(packetfunctions_sameAddress(IPv6,&(routes_vars.routes[posi].addr_128b)))){
				
				
		if (routes_vars.routes[posi].DAOSequence != DAOS){
                    //printf("+++ New DAOSequence...\n");
                }
				
                if (routes_vars.routes[posi].PathSequence != PathS){
                    //printf("+++ New PathSequence...\n");
                }
				
                if (!(packetfunctions_sameAddress(IPv6,&(routes_vars.routes[posi].addr_128b)))){
                    //printf("+++ New Orig-Publisher...\n");
                }
				
                //printf("Updating Route...\n");
                // update this route
                routes_vars.routes[posi].used                      = TRUE;
                routes_vars.routes[posi].advertneighinf            = 0;
                memcpy(&routes_vars.routes[posi].addr_128b,IPv6,sizeof(open_addr_t));
                (&routes_vars.routes[posi].addr_128b)->type=ADDR_128B;
                memcpy(&routes_vars.routes[posi].addr_64b,MAC64b,sizeof(open_addr_t));
                (&routes_vars.routes[posi].addr_64b)->type=ADDR_64B;
                routes_vars.routes[posi].retcount                  = 0;
                routes_vars.routes[posi].DAOSequence               = DAOS;
                routes_vars.routes[posi].PathSequence              = PathS;
                routes_vars.routes[posi].PathLifetime              = PathL;
                memcpy(&routes_vars.routes[posi].destination,destaddress,sizeof(open_addr_t));
                (&routes_vars.routes[posi].destination)->type=ADDR_128B;
                routes_vars.routes[posi].tosend                    = TRUE;
            }
        }  
        return;
   }
}

bool isRoute(open_addr_t* destroute) {
   uint8_t i=0;
   for (i=0;i<MAX_ROUTE_NUM;i++) {
      if (ThisRowMatch(destroute,i)) {
         return TRUE;
      }
   }
   return FALSE;
}

uint8_t posRoute(open_addr_t* destroute) {
   uint8_t i=0;
   for (i=0;i<MAX_ROUTE_NUM;i++) {
      if (ThisRowMatch(destroute,i)) {
         return i;
      }
   }
   return MAX_ROUTE_NUM+1;
}

void removeRoute(uint8_t routeIndex) {
   routes_vars.routes[routeIndex].used                      = FALSE;
   routes_vars.routes[routeIndex].advertneighinf            = 0;
   routes_vars.routes[routeIndex].addr_128b.type            = ADDR_NONE;
   routes_vars.routes[routeIndex].addr_64b.type             = ADDR_NONE;
   routes_vars.routes[routeIndex].retcount                  = 0;
   routes_vars.routes[routeIndex].DAOSequence               = 0;
   routes_vars.routes[routeIndex].PathSequence              = 0;
   routes_vars.routes[routeIndex].PathLifetime              = 0;
   routes_vars.routes[routeIndex].destination.type          = ADDR_NONE;
   routes_vars.routes[routeIndex].tosend                    = TRUE;
   routes_vars.routes[routeIndex].scount                    = 0;
}

uint8_t routes_getNumRoutes() {
   uint8_t i;
   uint8_t returnVal;
   
   returnVal=0;
   for (i=0;i<MAX_ROUTE_NUM;i++) {
      if (routes_vars.routes[i].used==TRUE) {
         returnVal++;
      }
   }
   return returnVal;
}


void routetable_setRTPeriod(uint16_t RTPeriod){
   uint32_t        RTPeriodRandom;
   
   routes_vars.RTPeriod = RTPeriod;
   RTPeriodRandom = routes_vars.RTPeriod - 0x80 + (openrandom_get16b()&0xff);
   opentimers_setPeriod(
       routes_vars.timerIdRT,
       TIME_MS,
       RTPeriodRandom
   );
}

/**
\brief Route Table timer callback function.

\note This function is executed in interrupt context, and should only push a
   task.
*/
void routetable_timer_cb(opentimer_id_t id) {
   scheduler_push_task(routetable_timer_task,TASKPRIO_RPL);
}

/**
\brief Handler for Route Table timer event.

\note This function is executed in task context, called by the scheduler.
*/
void routetable_timer_task() {
   uint32_t        RTPeriod;
   
   // Works only in Storing-Mode
   if (RPLMODE==1){
    // read Route-Table
    routetable_read();
   
    // arm the Route-Table timer with this new value
    RTPeriod = routes_vars.RTPeriod - 0x80 + (openrandom_get16b()&0xff);
    opentimers_setPeriod(
        routes_vars.timerIdRT,
        TIME_MS,
        RTPeriod
    );

   }
   
}

void routetable_read(){
   uint8_t  i,posi;
   
    printf("**** Reading Routing-Table!! -- ### ID-MOTE -- ");
    for (i=0;i<LENGTH_ADDR64b;i++) {
        printf(" %X",(&idmanager_vars.my64bID)->addr_64b[i]);  
    }
    printf ("\n");
    
    for (posi=0;posi<MAX_ROUTE_NUM;posi++) {
       if (routes_vars.routes[posi].used==TRUE) {
           printf("**** Reading Routing-Table!! -- PathLifetime -- %X",routes_vars.routes[posi].PathLifetime);
           printf(" ++ Route-MOTE-Address -- ");
           for (i=0;i<LENGTH_ADDR128b;i++) {
           printf(" %X",(&routes_vars.routes[posi].destination)->addr_128b[i]);  
           }
           printf ("\n");
           
           
           routes_vars.routes[posi].PathLifetime       = routes_vars.routes[posi].PathLifetime - RTAGING;
           // If PathLifetime is 0 or less remove the Route
           if (routes_vars.routes[posi].PathLifetime <= 0){
               removeRoute(posi);
           }
       }
    
    }
}

//=========================== helpers =========================================

bool ThisRowMatch(open_addr_t* address, uint8_t rowNumber) {

    return routes_vars.routes[rowNumber].used &&
		   packetfunctions_sameAddress(address,&routes_vars.routes[rowNumber].destination);
		   //packetfunctions_equalAddress(address,&routes_vars.routes[rowNumber].destination);

}