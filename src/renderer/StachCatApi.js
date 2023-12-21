/* eslint-disable prettier/prettier */
/* eslint-disable no-console */
/* eslint-disable no-shadow */
/* eslint-disable no-restricted-syntax */
/* eslint-disable no-return-await */
/* eslint-disable no-param-reassign */
/* eslint-disable no-use-before-define */
/* eslint-disable no-underscore-dangle */
/* eslint-disable no-await-in-loop */
/* eslint-disable no-plusplus */
/* eslint-disable camelcase */
const axios = require('axios');
const crypto = require('crypto');
const socketio = require('socket.io-client');
const request = require('request');

class StashCatClient {
  constructor(device_id, client_key, user_id, hidden_id) {
    this.base_url = "https://api.stashcat.com";
    this.push_url = "https://push.stashcat.com";

    this.headers = {
      "Accept": "application/json, text/plain, */*",
      "Accept-Encoding": "gzip, deflate, br",
      "Accept-Language": "en-US,en;q=0.5",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
      "User-Agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Mobile Safari/537.36",
    };

    this.private_key = null;
    this._key_cache = {};

    if (device_id === undefined) {
      device_id = [...Array(32)].map(() => Math.random().toString(36)[2]).join('');
    }

    this.device_id = device_id;
    this.client_key = client_key;
    this.user_id = user_id;
    this.hidden_id = hidden_id;
  }

  async _post(url, data, include_auth=true) {
    data.device_id = this.device_id;

    if (include_auth) {
        data.client_key = this.client_key;
    }

    try {
        const response = await axios.post(`${this.base_url}/${url}`, data, { headers: this.headers });
        const resp_data = response.data;

        if (resp_data.status.value !== "OK") {
            throw new Error(resp_data.status.message);
        }

        return resp_data.payload;
    } catch (error) {
        throw new Error(error);
    }
  }

  async login(username, password) {
    const data = await this._post("auth/login", {
      email: username,
      password,
      app_name: "schul.cloud-browser-MS-Edge-Chromium:116.0.1938.69-5.10.0",
      encrypted: true,
      callable: true,
    }, false);

    this.client_key = data.client_key;
    this.user_id = data.userinfo.id;
    this.hidden_id = data.userinfo.socket_id;

    return data;
  }

  get_socket() {
    if (!socketio) {
      throw new Error("SocketIO not available in this environment");
    }

    const sio = socketio(this.push_url);

    sio.on("connect", () => {
      sio.emit("userid", { hidden_id: this.hidden_id, device_id: this.device_id, client_key: this.client_key });
    });

    return sio;
  }

  async check() {
    await this._post("auth/check", { app_name: "schul.cloud-browser-MS-Edge-Chromium:116.0.1938.69-5.10.0", encrypted: true, callable: true });
  }

  async open_private_key(encryption_password) {
    const data = await this._post("security/get_private_key", {});

    const private_key_field = JSON.parse(data.keys.private_key);

     // there might be an unescaping bug here....
     const passphraseBuffer = Buffer.from(encryption_password);
     const privateKeyBuffer = Buffer.from(private_key_field.private, 'base64');

     try{
         const privateKeyDecryptedObj = crypto.privateDecrypt({ key: privateKeyBuffer, passphrase: passphraseBuffer }, privateKeyBuffer);
         this.private_key = crypto.createPrivateKey(privateKeyDecryptedObj);
     }catch(error){
         throw new Error(error);
     }
  }

  async get_open_conversations(limit=30, offset=0) {
    const data = await this._post("message/conversations", { limit, offset, archive: 0 });
    return data.conversations;
  }

  async search_user(search, limit=50, offset=0) {
    const data = await this._post("users/listing", {
      limit,
      offset,
      key_hashes: false,
      search,
      sorting: ["first_name_asc", "last_name_asc"],
      exclude_user_ids: [],
      group_ids: [],
    });
    return data.users;
  }

  async user_info(user_id) {
    const data = await this._post("users/info", { user_id, withkey: true });
    return data.user;
  }

  async open_conversation(members) {
    const conversation_key = crypto.randomBytes(32);

    const receivers = [];

    // Always add ourselves
    const encryptor = crypto.createCipheriv('aes-256-cbc', Buffer.from(this.private_key.publicKey.export({type:'pkcs1', format:'pem'})), Buffer.from([]));

    receivers.push({
        id : parseInt(this.user_id, 10),
        key : Buffer.concat([encryptor.update(conversation_key), encryptor.final()]).toString('base64')
      });



    for (let i=0; i<members.length; i++) {
        const pubkey = crypto.createPublicKey(Buffer.from(members[i].public_key));
        const encryptorForMember = crypto.createCipheriv('aes-256-cbc', pubkey.export({type:'pkcs1', format:'pem'}), Buffer.from([]));
        receivers.push({
            id : parseInt(members[i].id, 10),
            key : Buffer.concat([encryptorForMember.update(conversation_key), encryptorForMember.final()]).toString('base64')
          });
    }

    const data = await this._post("message/createEncryptedConversation", {
      members: JSON.stringify(receivers),
    });

    const {conversation} = data;
    this._key_cache[["conversation", conversation.id]] = conversation.key;
    return conversation;
  }

  async get_messages(source, limit=30, offset=0) {
    const data = await this._post("message/content", {
      [`${source[0]}_id`]: source[1],
      source: source[0],
      limit,
      offset,
    });

    const conversation_key = this._get_conversation_key(source);

    const messages = [];
    for (const message of data.messages) {
      if (message.kind === "message" && message.encrypted) {
        if (message.text !== null) {
          message.text_decrypted = _decrypt_aes(
            Buffer.from(message.text, 'hex'),
            conversation_key,
            Buffer.from(message.iv, 'hex')
          ).toString();
        }

        if (message.location.encrypted) {
          message.location.latitude_decrypted = _decrypt_aes(
            Buffer.from(message.location.latitude, 'hex'),
            conversation_key,
            Buffer.from(message.location.iv, 'hex')
          ).toString();

          message.location.longitude_decrypted = _decrypt_aes(
              Buffer.from(message.location.longitude, 'hex'),
              conversation_key,
              Buffer.from(message.location.iv, 'hex')
           ).toString();
         }
       }

       messages.push(message);
     }
     return messages;
   }

   async get_companies() {
     const data = await this._post("company/member", { no_cache: true });
     return data.companies;
   }

   async get_channels(company_id) {
     const data = await this._post("channels/subscripted", { company: company_id });
     return data.channels;
   }

   async _get_conversation_key(target) {
    let encrypted_key = this._key_cache[target];
     try {
       if (!encrypted_key) throw new Error("Encrypted key not found");
       const decryptor = crypto.createDecipheriv('aes-256-cbc', this.private_key, Buffer.from([]));
       return Buffer.concat([decryptor.update(Buffer.from(encrypted_key, 'base64')), decryptor.final()]);
     } catch (error) {
       if (target[0] === "conversation") {
         const data = await this._post("message/conversation", { conversation_id: target[1] });
         encrypted_key = data.conversation.key;
       } else if (target[0] === "channel") {
         const data = await this._post("channels/info", { channel_id: target[1], without_members: true });
         encrypted_key = data.channels.key;
       } else {
         throw new Error("Invalid target");
       }

       this._key_cache[target] = encrypted_key;

       const decryptor = crypto.createDecipheriv('aes-256-cbc', this.private_key, Buffer.from([]));

       return Buffer.concat([decryptor.update(Buffer.from(encrypted_key, 'base64')), decryptor.final()]);
     }
   }

   async send_msg(target, message, files=null, location=null) {
     files = files || [];

     const iv = crypto.randomBytes(16);
     const conversation_key = this._get_conversation_key(target);

     const payload = {
      client_key: this.client_key,
      device_id: this.device_id,
      target: target[0],
      [`${target[0]}_id`]: target[1],
      text: _encrypt_aes(Buffer.from(message), conversation_key, iv).toString('hex'),
      iv: iv.toString('hex'),
      files: JSON.stringify(files),
      url: "[]",
      type: "text",
      verification: "",
      encrypted: true,
     };

     if (location) {
       payload.latitude = _encrypt_aes(Buffer.from(location[0].toString()), conversation_key, iv).toString('hex');
       payload.longitude = _encrypt_aes(Buffer.from(location[1].toString()), conversation_key, iv).toString('hex');
     }

     return await this._post("message/send", payload);
   }

   send_msg_to_channel(channel_id, message) {
     return this.send_msg(["channel", channel_id], message);
   }

   send_msg_to_user(conversation_id, message) {
     return this.send_msg(["conversation", conversation_id], message);
   }

   async upload_file(target, file, filename, content_type="application/octet-stream", media_size=null) {
     media_size = media_size || [null, null];
     const iv = crypto.randomBytes(16);
     const file_key = crypto.randomBytes(32);

    const content = await file.read();
    const chunkSize = 5 * 1024 * 1024;
    const upload_uuid = crypto.randomUUID();
    let ct_bytes;
    let file_data;

    for (let nr=0; nr < -Math.floor(content.length / -chunkSize); nr++) {
        const start_idx = nr * chunkSize;
        const end_idx = (nr + 1) * chunkSize;
        const chunk = content.slice(start_idx, end_idx);

        ct_bytes = _encrypt_aes(chunk,
            file_key,
            iv
          );

        file_data = await this._post("file/upload", {
          resumableChunkNumber: nr,
          resumableChunkSize: chunkSize,
          resumableCurrentChunkSize: ct_bytes.length,
          resumableTotalSize: content.length,
          resumableType: content_type,
          resumableIdentifier: upload_uuid,
          resumableFilename: filename,
          resumableRelativePath: filename,
          resumableTotalChunks: -Math.floor(content.length / -chunkSize),
          folder: 0,
          type: target[0],
          type_id: target[1],
          encrypted: true,
          iv: iv.toString('hex'),
          media_width: media_size[0],
          media_height: media_size[1],
        }, { file : Buffer.from(ct_bytes) });
    }
    const decryptedKey = await _decrypt_aes(Buffer.from(file_key), this._get_conversation_key(target), Buffer.from(iv));

    this._post("security/set_file_access_key", {
        file_id: file_data.id,
        target: target[0],
        target_id: target[1],
        key : decryptedKey.toString('hex'),
        iv : iv.toString('hex'),
    });
    return file_data;
  }
}

function _encrypt_aes(plain, key, iv) {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([cipher.update(plain), cipher.final()]);
}

function _decrypt_aes(cipher, key, iv) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([decipher.update(cipher), decipher.final()]);
}

function setup_logging(debug=false) {
  if (debug) {
    process.env.NODE_DEBUG = "http";
    request.debug = true;
  }
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length < 3) {
    console.log("Please provide username, password, and encryption key as command line arguments");
    return;
  }

  const username = args[0];
  const password = args[1];
  const encryption_key = args[2];

  setup_logging(args.includes("--debug"));

  const client = new StashCatClient();

  try {
    const payload = await client.login(username, password);

    if (payload) {
      await client.open_private_key(encryption_key);

      const socket = client.get_socket();

      socket.on("*", (...args) => {
        // Blacklist spammy events
        if (args[0] === "online_status_change") {
          return;
        }

        console.log("received", ...args);
      });

      socket.on("connect", () => {
        socket.emit("userid", { hidden_id: client.hidden_id, device_id: client.device_id, client_key: client.client_key });
      });

      await new Promise((resolve) => {
        socket.on("disconnect", () => {
          resolve();
        });

        process.on('SIGINT', () => {
          socket.disconnect();
          resolve();
        });
      });
    }
  } catch (error) {
    console.error(error.message);
  }
}

main();
