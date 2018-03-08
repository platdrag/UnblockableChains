//
// ecnc web UI
//
var app = new Vue({
   el : '.body_wrapper',
   data : { 
     c_map: {}, // {'a': {'addr': 0}},
     cmd_map: {},
     c_index: {},
     time: '',
     server_status: '',
     in_client_shell_cmd: '',
   },

   mounted: function() {

       this.$ws = new WebSocket('ws://127.0.0.1:5000/echo');
       this.$ws.onmessage = function(event) {

           var text = "";
           var msg = JSON.parse(event.data);
           var time = new Date(msg.date);
           var timeStr = time.toLocaleTimeString();

           new_client_ph_id = '__new-client-placeholder-id__' // new client tmp id hack

           switch(msg.msg_type) {

             case 's.hello':
                console.log('server ws connection established')
                break;

             case 's.client-update':
               client = msg.payload;
               if(new_client_ph_id == client.addr && 'kit-generation-end' == client.status){
                  Vue.delete(app.c_map, new_client_ph_id);
                  break;
               }
               Vue.set(app.c_map, client.addr, client);
               app.c_index_update(client, true)
               console.log('rx: new-client: ' + client.addr)
               break;

             case 'c.cmd_update':
               cmd_set = msg.payload.cmd_set
               cmd_set.map(cmd => {
                  Vue.set(app.cmd_map, cmd.id, cmd);
               });
               console.log('c.work-tx: ' + JSON.stringify(cmd_set))
               break;

             case 'c.work-rx':
               cmd = msg.payload
               Vue.set(app.cmd_map, cmd.id, cmd)
               console.log('c.work-rx: ' + JSON.stringify(cmd))
               break;
           }
       };

      // clock
      var date_opt = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',hour: 'numeric', minute: 'numeric', second: 'numeric' };
      setInterval(function() {
          this.$data.time = new Date().toLocaleDateString("en-US", date_opt);
      }.bind(this), 1000);

      //
      // register status poller
      //
      this.poll_status = setInterval(function() {
      Vue.http.get('/status').then(
      r => { this.server_status = r.body;
      },
      e => { this.server_status = 'n/a' });
      }.bind(this), 3000);

   },

   methods : {

      c_index_update: function(client, include, event) {
          if (include){
             Vue.set(app.c_index, client.addr, client);
             console.info('c-index: client added: ' + client.addr)
          }else{
             Vue.delete(app.c_index, client.addr)
             console.info('c-index: client rm: ' + client.addr)
          };
      },
      
       btn_shutdown : function() {
           clearInterval(this.poll_status);
                  
           // TODO: shutdown server
           console.info('webapp shutdown');
        },
        
      /*
       * server: gen client kit
       */
      btn_ws_s_gen_client_kit : function() {
          var msg = {'msg_type':'s.gen-client-kit'};
       this.$ws.send(JSON.stringify(msg)); 
      },

      btn_ws_s_new_client: function(val) { 
         var msg = {'msg_type': 's.new-client'};
         this.$ws.send(JSON.stringify(msg)); 
      },

      /*
       * client: add work
       */
      btn_ws_c_work_tx: function(val) { 
          var msg = {'msg_type':'c.work-tx', 
                     'payload': { 'c_addr_set': Object.keys(app.c_index),
                                  'shell_cmd': this.in_client_shell_cmd,
                     }
          };
          this.$ws.send(JSON.stringify(msg)); 
      },

      /*
       * client: receive work output
       */
      btn_ws_c_work_rx: function(val) { 
          var msg = {'msg_type':'c.work-rx'};
          this.$ws.send(JSON.stringify(msg));
      },

   },

});

console.log('ecnc-ui client initialized')
