#define REPORT_SERVER_PORT 1001

control State_Machine(inout header_t hdr,
  inout ingress_metadata_t ig_md,
  in ingress_intrinsic_metadata_t ig_intr_md,
  in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
  inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    // to store the value for the states
    bit<32> curr_state = 0;
    bit<32> time_flag = 0;

    // to store the value for the hash index
    ip4Addr_t hash_key;
    bit<32> hash_index;
    bit<32> storage_index;

    // variable to set the direction of traffic flow
    bit<8>  direction = 0;
    bit<8>  result = 0;

    // register to store the device detection
    Register<bit<32>, _>(DEVICES) count_devices;
    RegisterAction<bit<32>, _, bit<32>>(count_devices) increment_counter = {
      void apply (inout bit<32> value) {
        bit<32> in_value = value;
	    value = in_value + 1;
      }
    };

    // register to store states
    Register<bit<32>, _>(CONNECTIONS) reg_state;
    RegisterAction<bit<32>, _, bit<32>>(reg_state) read_state = {
      void apply (inout bit<32> value, out bit<32> rv) {
        rv = value;
      }
    };
    RegisterAction<bit<32>, _, bit<32>>(reg_state) update_state = {
      void apply (inout bit<32> value) {
        value = ig_md.resub_hdr.next_state;
      }
    };

    // register to store timestamps
    Register<bit<32>, _>(CONNECTIONS) timers;
    RegisterAction<bit<32>, _, bit<32>>(timers) check_timer = {
      void apply (inout bit<32> value, out bit<32> rv) {
        rv = 0;
        if (value == 0) {
          value = TIMESTAMP;
        }
        else {
          bit<32> elapsed_time = TIMESTAMP - value;

          if (elapsed_time > TIMEOUT) {
            value = 0;
            rv = 1;
          }
        }
      }
    };
    RegisterAction<bit<32>, _, bit<32>>(timers) reset_timer = {
      void apply (inout bit<32> value) {
      	value = 0;
      }
    };

    //Record device in packet
    action device_detected(ip4Addr_t src) {
        hdr.ipv4.srcAddr = src;
        hdr.ipv4.dstAddr = 0x0A320006;
        hdr.tcp.srcPort = (bit<16>) ig_md.resub_hdr.device_id;
        hdr.tcp.dstPort = REPORT_SERVER_PORT;
    }

    //get the next state
    action set_state(bit<32> new_state, bit<(DEV_WIDTH)> d_id) {
      ig_dprsr_md.resubmit_type = 3w1;
      ig_md.resub_hdr.next_state = new_state;
      ig_md.resub_hdr.device_id = d_id;
    }

    // get the direction of the packet
    action set_direction(bit<8> dir) {
      direction = dir;
    }

    Hash<bit<32>>(HashAlgorithm_t.CRC32) sym_hash;

    // table to check the direction of traffic flow
    table check_direction {
      key = {
        hdr.ipv4.srcAddr: ternary;
        hdr.ipv4.dstAddr: ternary;
      }
      actions = {
        set_direction;
      }
      size = 2;
    }

    // table to add a transition
    @pack(2)
    table FSM_transition_table {
      key = {
        hdr.ipv4.totalLen: exact;
        curr_state: exact;
        direction: exact;
      }
      actions = {
        set_state;
	    NoAction;
      }

      size = 16384;
      @defaultonly default_action = NoAction();
    }

    apply {
        //Get direction and hash
        check_direction.apply();
    	if (direction == 1) {
    	    hash_key = hdr.ipv4.dstAddr;
    	}
    	else {
    	    hash_key = hdr.ipv4.srcAddr;
    	}

    	hash_index = (bit<32>)(sym_hash.get({hash_key})[15:0]);

        //Update if needed
    	if (ig_intr_md.resubmit_flag == 1) {

		        increment_counter.execute(31); //Measure resubmits
                update_state.execute(hash_index);

                //Forward device detect packet
                if (ig_md.resub_hdr.device_id != 0) {
                    device_detected(hash_key);
                }
        }
        else {
            // lookup the state register and store the
            // value in curr_state
            curr_state = read_state.execute(hash_index);

            if (FSM_transition_table.apply().hit) {
            if (ig_md.resub_hdr.next_state == 0) {
              result = 1; //Record the hit

              //"Report" device
              increment_counter.execute(ig_md.resub_hdr.device_id);
            }
            }

            //check timer
            if (result == 1) {
              reset_timer.execute(hash_index);
            }
            else {
              time_flag = check_timer.execute(hash_index);

              if (time_flag == 1) {
                  set_state(0, 0);
              }
            }
        }
    }
}
