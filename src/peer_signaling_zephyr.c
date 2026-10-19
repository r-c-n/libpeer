#ifndef DISABLE_PEER_SIGNALING
#include <assert.h>
#include <cJSON.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <zephyr/random/random.h>
#include <zephyr/posix/arpa/inet.h>
#include <zephyr/posix/netdb.h>
#include <zephyr/net/http/client.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/posix/poll.h>

#include "base64.h"
#include "config.h"
#include "peer_signaling.h"
#include "ports.h"
#include "ssl_transport.h"
#include "utils.h"

#define KEEP_ALIVE_TIMEOUT_SECONDS 60
#define CONNACK_RECV_TIMEOUT_MS 1000

#define PATH_MAX_LEN 128
#define HOST_MAX_LEN 64
#define URL_MAX_LEN (PATH_MAX_LEN + HOST_MAX_LEN + 8)
#define TOPIC_MAX_LEN URL_MAX_LEN
#define TOKEN_MAX_LEN 256

#define RPC_VERSION "2.0"
#define RPC_METHOD_STATE "state"
#define RPC_METHOD_OFFER "offer"
#define RPC_METHOD_ANSWER "answer"
#define RPC_METHOD_CLOSE "close"

#define RPC_ERROR_PARSE_ERROR "{\"code\":-32700,\"message\":\"Parse error\"}"
#define RPC_ERROR_INVALID_REQUEST "{\"code\":-32600,\"message\":\"Invalid Request\"}"
#define RPC_ERROR_METHOD_NOT_FOUND "{\"code\":-32601,\"message\":\"Method not found\"}"
#define RPC_ERROR_INVALID_PARAMS "{\"code\":-32602,\"message\":\"Invalid params\"}"
#define RPC_ERROR_INTERNAL_ERROR "{\"code\":-32603,\"message\":\"Internal error\"}"

typedef enum {
  PROTO_MQTT,
  PROTO_HTTP,
} SignalingProto;

typedef struct PeerSignaling {
  NetworkContext_t net_ctx;

  struct mqtt_client mqtt;
  bool mqtt_connected;
  struct sockaddr_in  broker;

  uint8_t mqtt_rx_buf[CONFIG_MQTT_BUFFER_SIZE];
  uint8_t mqtt_tx_buf[CONFIG_MQTT_BUFFER_SIZE];
  uint8_t mqtt_payload_buf[CONFIG_MQTT_BUFFER_SIZE];
  uint8_t http_buf[CONFIG_HTTP_BUFFER_SIZE];

  char subtopic[TOPIC_MAX_LEN];
  char pubtopic[TOPIC_MAX_LEN];

  uint16_t packet_id;
  int id;

  int proto;
  int port;
  char host[HOST_MAX_LEN];
  char path[PATH_MAX_LEN];
  char token[TOKEN_MAX_LEN];
  char client_id[32];

  PeerConnection* pc;

} PeerSignaling;

static PeerSignaling g_ps = {0};

static int peer_signaling_resolve_token(const char* token, char* username, char* password) {
  char plaintext[TOKEN_MAX_LEN] = {0};
  char* colon;

  if (token == NULL || strlen(token) == 0) {
    LOGW("Invalid token");
    return -1;
  }
  base64_decode(token, strlen(token), (unsigned char*)plaintext, sizeof(plaintext));
  colon = strchr(plaintext, ':');
  if (colon == NULL) {
    LOGW("Invalid token: %s", token);
    return -1;
  }

  strncpy(username, plaintext, colon - plaintext);
  strncpy(password, colon + 1, strlen(colon + 1));
  LOGD("Username: %s, Password: %s", username, password);
  return 0;
}

static int peer_signaling_resolve_url(const char* url, char* host, int* port, char* path) {
  char *port_start, *path_start;
  int proto = PROTO_MQTT;

  if (url == NULL || strlen(url) == 0) {
    LOGW("Invalid URL");
    return -1;
  }

  if (strncmp(url, "mqtts://", sizeof("mqtts://") - 1) == 0) {
    *port = 8883;
    url += sizeof("mqtts://") - 1;
  } else if (strncmp(url, "https://", sizeof("https://") - 1) == 0) {
    *port = 443;
    url += sizeof("https://") - 1;
    proto = PROTO_HTTP;
  } else if (strncmp(url, "mqtt://", sizeof("mqtt://") - 1) == 0) {
    *port = 1883;
    url += sizeof("mqtt://") - 1;
  } else if (strncmp(url, "http://", sizeof("http://") - 1) == 0) {
    *port = 80;
    url += sizeof("http://") - 1;
    proto = PROTO_HTTP;
  } else {
    LOGW("Invalid URL: %s", url);
    return -1;
  }

  port_start = strchr(url, ':');
  path_start = strchr(url, '/');

  if (port_start != NULL && path_start != NULL && port_start < path_start) {
    strncpy(host, url, port_start - url);
    strncpy(path, path_start, strlen(path_start));
    *port = atoi(port_start + 1);
  } else if (port_start == NULL && path_start != NULL) {
    strncpy(host, url, path_start - url);
    strncpy(path, path_start, strlen(path_start));
  } else if (port_start != NULL && path_start == NULL) {
    strncpy(host, url, port_start - url);
    *port = atoi(port_start + 1);
  } else {
    strncpy(host, url, strlen(url));
  }

  LOGI("Host: %s, Port: %d, Path: %s", host, *port, path);
  return proto;
}

static void peer_signaling_mqtt_publish(struct mqtt_client* mqtt, char* message) {
  struct mqtt_publish_param param;
  int ret;

  param.message.topic.qos = MQTT_QOS_0_AT_MOST_ONCE;
  param.message.topic.topic.utf8 = (uint8_t *)g_ps.pubtopic;
  param.message.topic.topic.size = strlen(g_ps.pubtopic);
  param.message.payload.data = message;
  param.message.payload.len = strlen(message);
  param.message_id = sys_rand16_get();
  param.dup_flag = 0;
  param.retain_flag = 0;

  ret = mqtt_publish(mqtt, &param);
  if (ret) {
    LOGE("mqtt_publish() failed: %d", ret);
  }
}

static void peer_signaling_on_pub_event(const char* msg, size_t size) {
  cJSON *req, *res, *item, *result, *error;
  int id = -1;
  char* payload = NULL;
  PeerConnectionState state;

  req = res = item = result = error = NULL;
  state = peer_connection_get_state(g_ps.pc);
  do {
    req = cJSON_Parse(msg);
    if (!req) {
      error = cJSON_CreateRaw(RPC_ERROR_PARSE_ERROR);
      LOGW("Parse json failed");
      break;
    }

    item = cJSON_GetObjectItem(req, "id");
    if (!item && !cJSON_IsNumber(item)) {
      error = cJSON_CreateRaw(RPC_ERROR_INVALID_REQUEST);
      LOGW("Cannot find id");
      break;
    }

    id = item->valueint;

    item = cJSON_GetObjectItem(req, "method");
    if (!item && cJSON_IsString(item)) {
      error = cJSON_CreateRaw(RPC_ERROR_INVALID_REQUEST);
      LOGW("Cannot find method");
      break;
    }

    if (strcmp(item->valuestring, RPC_METHOD_OFFER) == 0) {
      switch (state) {
        case PEER_CONNECTION_NEW:
        case PEER_CONNECTION_DISCONNECTED:
        case PEER_CONNECTION_FAILED:
        case PEER_CONNECTION_CLOSED: {
          g_ps.id = id;
          peer_connection_create_offer(g_ps.pc);
        } break;
        default: {
          error = cJSON_CreateRaw(RPC_ERROR_INTERNAL_ERROR);
        } break;
      }
    } else if (strcmp(item->valuestring, RPC_METHOD_ANSWER) == 0) {
      item = cJSON_GetObjectItem(req, "params");
      if (!item && !cJSON_IsString(item)) {
        error = cJSON_CreateRaw(RPC_ERROR_INVALID_PARAMS);
        LOGW("Cannot find params");
        break;
      }

      peer_connection_set_remote_description(g_ps.pc, item->valuestring, SDP_TYPE_ANSWER);

    } else if (strcmp(item->valuestring, RPC_METHOD_STATE) == 0) {
      result = cJSON_CreateString(peer_connection_state_to_string(state));

    } else if (strcmp(item->valuestring, RPC_METHOD_CLOSE) == 0) {
      peer_connection_close(g_ps.pc);
      result = cJSON_CreateString("");

    } else {
      error = cJSON_CreateRaw(RPC_ERROR_METHOD_NOT_FOUND);
      LOGW("Unsupport method");
    }

  } while (0);

  if (result || error) {
    res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "jsonrpc", RPC_VERSION);
    cJSON_AddNumberToObject(res, "id", id);

    if (result) {
      cJSON_AddItemToObject(res, "result", result);
    } else if (error) {
      cJSON_AddItemToObject(res, "error", error);
    }

    payload = cJSON_PrintUnformatted(res);

    if (payload) {
      peer_signaling_mqtt_publish(&g_ps.mqtt, payload);
      free(payload);
    }
    cJSON_Delete(res);
  }

  if (req) {
    cJSON_Delete(req);
  }
}

static void peer_signaling_mqtt_event_cb(struct mqtt_client *client,
                                         const struct mqtt_evt *evt) {
  switch (evt->type) {
    case MQTT_EVT_CONNACK:
      if (evt->result == 0) {
        LOGD("MQTT connected");
	g_ps.mqtt_connected = true;
      } else {
        LOGE("MQTT CONNACK error %d", evt->result);
      }
      break;
    case MQTT_EVT_DISCONNECT:
      LOGD("MQTT disconnected");
      g_ps.mqtt_connected = false;
      break;
    case MQTT_EVT_PUBLISH:
      int len = evt->param.publish.message.payload.len;
      int ret;
      struct mqtt_puback_param puback;

      LOGD("MQTT received message: %d, %d bytes", evt->result, len);
      if (len >= sizeof(g_ps.mqtt_payload_buf)) {
	LOGE("MQTT payload is bigger than buffer (%d) and will be truncated", len);
        len = sizeof(g_ps.mqtt_payload_buf) - 1;
      }
      ret = mqtt_read_publish_payload(&g_ps.mqtt, g_ps.mqtt_payload_buf, len);
      if (ret < 0 && ret != -EAGAIN) {
        LOGE("failure to read payload");
        break;
      }
      g_ps.mqtt_payload_buf[ret] = '\0';
      LOGD("payload: %s", g_ps.mqtt_payload_buf);
      peer_signaling_on_pub_event(g_ps.mqtt_payload_buf, len);
      if (evt->param.publish.message.topic.qos == MQTT_QOS_1_AT_LEAST_ONCE) {
        puback.message_id = evt->param.publish.message_id;
        mqtt_publish_qos1_ack(&g_ps.mqtt, &puback);
      }
      break;
    case MQTT_EVT_SUBACK:
      LOGD("MQTT subscribed");
      break;
    case MQTT_EVT_PINGRESP:
      LOGD("Received MQTT ping response from server");
      break;
    default:
      LOGI("MQTT event %d: Not implemented", evt->type);
  }
}

static int peer_signaling_mqtt_connect(const char* hostname, int port) {
  int rc;
  struct addrinfo *res;
  static char username_buf[TOKEN_MAX_LEN] = {0};
  static char password_buf[TOKEN_MAX_LEN] = {0};
  static struct mqtt_utf8 username;
  static struct mqtt_utf8 password;

  const struct addrinfo hints = {
    .ai_family = AF_INET,
    .ai_socktype = SOCK_STREAM
  };

  rc = getaddrinfo(hostname, NULL, &hints, &res);
  if (rc != 0) {
    LOGE("Failed to resolve broker hostname [%s]", gai_strerror(rc));
    return -EIO;
  }
  if (res == NULL) {
	  LOGE("Broker address not found");
	  return -ENOENT;
  }
  memcpy(&g_ps.broker, res->ai_addr, sizeof(g_ps.broker));
  g_ps.broker.sin_port = htons((uint16_t)port);
  freeaddrinfo(res);

  if (strlen(g_ps.token) > 0) {
    peer_signaling_resolve_token(g_ps.token, username_buf, password_buf);
    if (username_buf[0] != 0) {
      username.utf8 = (uint8_t *)username_buf;
      username.size = strlen(username_buf);
    }
    if (password_buf[0] != 0) {
      password.utf8 = (uint8_t *)password_buf;
      password.size = strlen(password_buf);
    }
  }

  mqtt_client_init(&g_ps.mqtt);
  g_ps.mqtt.broker = (struct sockaddr *)&g_ps.broker;
  g_ps.mqtt.evt_cb = peer_signaling_mqtt_event_cb;
  g_ps.mqtt.client_id.utf8 = (uint8_t *)g_ps.client_id;
  g_ps.mqtt.client_id.size = strlen(g_ps.client_id);
  if (username.size != 0) {
    g_ps.mqtt.user_name = &username;
  } else {
    g_ps.mqtt.user_name = NULL;
  }
  if (password.size != 0) {
    g_ps.mqtt.password = &password;
  } else {
    g_ps.mqtt.password = NULL;
  }
  g_ps.mqtt.keepalive = KEEP_ALIVE_TIMEOUT_SECONDS;
  g_ps.mqtt.rx_buf = g_ps.mqtt_rx_buf;
  g_ps.mqtt.rx_buf_size = sizeof(g_ps.mqtt_rx_buf);
  g_ps.mqtt.tx_buf = g_ps.mqtt_tx_buf;
  g_ps.mqtt.tx_buf_size = sizeof(g_ps.mqtt_tx_buf);
  g_ps.mqtt.protocol_version = MQTT_VERSION_3_1_1;

#if defined(CONFIG_MQTT_LIB_TLS)
  struct mqtt_sec_config *tls_config;

  g_ps.mqtt.transport.type = MQTT_TRANSPORT_SECURE;

  tls_config = &g_ps.mqtt.transport.tls.config;
  tls_config->peer_verify = TLS_PEER_VERIFY_OPTIONAL;
  tls_config->cipher_list = NULL;
  tls_config->cipher_count = 0;
  tls_config->sec_tag_list = NULL;
  tls_config->sec_tag_count = 0;
  tls_config->hostname = hostname;
#endif /* CONFIG_MQTT_LIB_TLS */

  rc = mqtt_connect(&g_ps.mqtt);
  if (rc) {
    LOGE("mqtt_connect failed: %d", rc);
    return -1;
  }

  /* Wait for CONNACK */
  int64_t deadline = k_uptime_get() + CONNACK_RECV_TIMEOUT_MS;
  while (!g_ps.mqtt_connected && k_uptime_get() < deadline) {
    mqtt_input(&g_ps.mqtt);
    k_msleep(50);
  }

  return g_ps.mqtt_connected ? 0 : -ETIMEDOUT;
}

static int peer_signaling_mqtt_subscribe(void) {
  int rc;

  struct mqtt_topic topic = {
    .topic = {
      .utf8 = (uint8_t *)g_ps.subtopic,
      .size = strlen(g_ps.subtopic),
    },
    .qos = MQTT_QOS_0_AT_MOST_ONCE,
  };
  struct mqtt_subscription_list sub = {
    .list = &topic,
    .list_count = 1,
    .message_id = sys_rand16_get(),
  };

  LOGD("Subscribing to %s", g_ps.subtopic);
  rc = mqtt_subscribe(&g_ps.mqtt, &sub);
  if (rc) {
    LOGE("mqtt_subscribe failed: %d", rc);
    return -1;
  }
  LOGD("Subscribed to %s", g_ps.subtopic);

  return rc;
}

static void peer_signaling_onicecandidate(char* description, void* userdata) {
  cJSON* res;
  char* payload;

  if (g_ps.id > 0) {
    res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "jsonrpc", RPC_VERSION);
    cJSON_AddNumberToObject(res, "id", g_ps.id);
    cJSON_AddStringToObject(res, "result", description);
    payload = cJSON_PrintUnformatted(res);
    if (payload) {
      peer_signaling_mqtt_publish(&g_ps.mqtt, payload);
      free(payload);
    }
    cJSON_Delete(res);
    g_ps.id = 0;
  } else {
    if (strlen(g_ps.token) > 0) {
      char cred[TOKEN_MAX_LEN + 10];
      memset(cred, 0, sizeof(cred));
      snprintf(cred, sizeof(cred), "Bearer %s", g_ps.token);
      //peer_signaling_http_post(g_ps.host, g_ps.path, g_ps.port, cred, description);
    } else {
      //peer_signaling_http_post(g_ps.host, g_ps.path, g_ps.port, "", description);
    }
  }
}

int peer_signaling_connect(const char* url, const char* token, PeerConnection* pc) {
  char* client_id;

  if ((g_ps.proto = peer_signaling_resolve_url(url, g_ps.host, &g_ps.port, g_ps.path)) < 0) {
    LOGE("Resolve URL failed");
  }

  if (token && strlen(token) > 0) {
    strncpy(g_ps.token, token, sizeof(g_ps.token));
  }

  g_ps.pc = pc;
  peer_connection_onicecandidate(g_ps.pc, peer_signaling_onicecandidate);

  switch (g_ps.proto) {
    case PROTO_MQTT: {
      client_id = strrchr(g_ps.path, '/');
      snprintf(g_ps.client_id, sizeof(g_ps.client_id), "%s", client_id + 1);
      snprintf(g_ps.subtopic, sizeof(g_ps.subtopic), "%s/invoke", g_ps.path);
      snprintf(g_ps.pubtopic, sizeof(g_ps.pubtopic), "%s/result", g_ps.path);
      if (peer_signaling_mqtt_connect(g_ps.host, g_ps.port) == 0) {
        peer_signaling_mqtt_subscribe();
      }
    } break;
    case PROTO_HTTP: {
      peer_connection_create_offer(g_ps.pc);
    } break;
    default: {
    } break;
  }

  return 0;
}

void peer_signaling_disconnect(void) {
  if (g_ps.proto == PROTO_MQTT) {
    int ret = mqtt_disconnect(&g_ps.mqtt, NULL);
    if (ret) {
      LOGE("mqtt_disconnect(): %d", ret);
      return;
    }
  }
  LOGI("Disconnected");
}

int peer_signaling_loop(void) {
  int rc;
  int timeout;
  struct pollfd fds;

  if (g_ps.proto == PROTO_MQTT && !g_ps.mqtt_connected) {
    return 1;
  }

  fds.fd = g_ps.mqtt.transport.tls.sock;
  fds.events = POLLIN;
  while (1) {
    timeout = mqtt_keepalive_time_left(&g_ps.mqtt);
    LOGD("poll (timeout: %d)", timeout);
    rc = poll(&fds, 1u, timeout);
    if (rc >= 0) {
      if (fds.revents & POLLIN) {
        rc = mqtt_input(&g_ps.mqtt);
	if (rc != 0) {
          LOGE("Failed to read MQTT input: %d", rc);
	  return -1;
	}
      }
      if (fds.revents & (POLLHUP | POLLERR)) {
        LOGE("Socket closed/error");
	return -1;
      }
      rc = mqtt_live(&g_ps.mqtt);
      if ((rc != 0) && (rc != -EAGAIN)) {
        LOGE("Failed to keep MQTT connection alive: %d", rc);
	return rc;
      }
    } else {
      LOGE("Poll failed: %d", rc);
      return -1;
    }
  }

  return 0;
}
#endif  // DISABLE_PEER_SIGNALING
