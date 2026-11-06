import c1_sd
"""Offline evidence checks. No process, filesystem, or network operations."""
import json
import re
import uuid
import xml.etree.ElementTree as ET
from decimal import Decimal
from offline_evidence import assess
from records import snapshot, TARGETS, unique


def result(status, reasons, **extra):
    return dict(status=status, reasons=reasons, **extra)


def guid(value):
    if isinstance(value, dict):
        value = '%08x-%04x-%04x-%s-%s' % (value['Data1'], value['Data2'], value['Data3'], bytes(value['Data4'][:2]).hex(), bytes(value['Data4'][2:]).hex())
    return str(uuid.UUID(value))


# Fixed symbolic GUID constants from third_party/wf/zguids.go.
_POLICY_SYMBOLS = {'FWPM_CONDITION_ALE_APP_ID': 'd78e1e87-8644-4ea5-9437-d809ecefc971', 'FWPM_CONDITION_ALE_EFFECTIVE_NAME': 'b1277b9a-b781-40fc-9671-e5f1b989f34e', 'FWPM_CONDITION_ALE_NAP_CONTEXT': '46275a9d-c03f-4d77-b784-1c57f4d02753', 'FWPM_CONDITION_ALE_ORIGINAL_APP_ID': '0e6cd086-e1fb-4212-842f-8a9f993fb3f6', 'FWPM_CONDITION_ALE_PACKAGE_ID': '71bc78fa-f17c-4997-a602-6abb261f351c', 'FWPM_CONDITION_ALE_PROMISCUOUS_MODE': '1c974776-7182-46e9-afd3-b02910e30334', 'FWPM_CONDITION_ALE_REAUTH_REASON': 'b482d227-1979-4a98-8044-18bbe6237542', 'FWPM_CONDITION_ALE_REMOTE_MACHINE_ID': '1aa47f51-7f93-4508-a271-81abb00c9cab', 'FWPM_CONDITION_ALE_REMOTE_USER_ID': 'f63073b7-0189-4ab0-95a4-6123cbfab862', 'FWPM_CONDITION_ALE_SECURITY_ATTRIBUTE_FQBN_VALUE': '37a57699-5883-4963-92b8-3e704688b0ad', 'FWPM_CONDITION_ALE_SIO_FIREWALL_SYSTEM_PORT': 'b9f4e088-cb98-4efb-a2c7-ad07332643db', 'FWPM_CONDITION_ALE_USER_ID': 'af043a0a-b34d-4f86-979c-c90371af6e66', 'FWPM_CONDITION_ARRIVAL_INTERFACE_INDEX': 'cc088db3-1792-4a71-b0f9-037d21cd828b', 'FWPM_CONDITION_ARRIVAL_INTERFACE_PROFILE_ID': 'cdfe6aab-c083-4142-8679-c08f95329c61', 'FWPM_CONDITION_ARRIVAL_INTERFACE_TYPE': '89f990de-e798-4e6d-ab76-7c9558292e6f', 'FWPM_CONDITION_ARRIVAL_TUNNEL_TYPE': '511166dc-7a8c-4aa7-b533-95ab59fb0340', 'FWPM_CONDITION_AUTHENTICATION_TYPE': 'eb458cd5-da7b-4ef9-8d43-7b0a840332f2', 'FWPM_CONDITION_BITMAP_INDEX_KEY': '0f36514c-3226-4a81-a214-2d518b04d08a', 'FWPM_CONDITION_BITMAP_IP_LOCAL_ADDRESS': '16ebc3df-957a-452e-a1fc-3d2ff6a730ba', 'FWPM_CONDITION_BITMAP_IP_LOCAL_PORT': '9f90a920-c3b5-4569-ba31-8bd3910dc656', 'FWPM_CONDITION_BITMAP_IP_REMOTE_ADDRESS': '33f00e25-8eec-4531-a005-41b911f62452', 'FWPM_CONDITION_BITMAP_IP_REMOTE_PORT': '2663d549-aaf2-46a2-8666-1e7667f86985', 'FWPM_CONDITION_CLIENT_CERT_KEY_LENGTH': 'a3ec00c7-05f4-4df7-91f2-5f60d91ff443', 'FWPM_CONDITION_CLIENT_CERT_OID': 'c491ad5e-f882-4283-b916-436b103ff4ad', 'FWPM_CONDITION_CLIENT_TOKEN': 'c228fc1e-403a-4478-be05-c9baa4c05ace', 'FWPM_CONDITION_COMPARTMENT_ID': '35a791ab-04ac-4ff2-a6bb-da6cfac71806', 'FWPM_CONDITION_CURRENT_PROFILE_ID': 'ab3033c9-c0e3-4759-937d-5758c65d4ae3', 'FWPM_CONDITION_DCOM_APP_ID': 'ff2e7b4d-3112-4770-b636-4d24ae3a6af2', 'FWPM_CONDITION_DESTINATION_INTERFACE_INDEX': '35cf6522-4139-45ee-a0d5-67b80949d879', 'FWPM_CONDITION_DESTINATION_SUB_INTERFACE_INDEX': '2b7d4399-d4c7-4738-a2f5-e994b43da388', 'FWPM_CONDITION_DIRECTION': '8784c146-ca97-44d6-9fd1-19fb1840cbf7', 'FWPM_CONDITION_EMBEDDED_LOCAL_ADDRESS_TYPE': '4672a468-8a0a-4202-abb4-849e92e66809', 'FWPM_CONDITION_EMBEDDED_LOCAL_PORT': 'bfca394d-acdb-484e-b8e6-2aff79757345', 'FWPM_CONDITION_EMBEDDED_PROTOCOL': '07784107-a29e-4c7b-9ec7-29c44afafdbc', 'FWPM_CONDITION_EMBEDDED_REMOTE_ADDRESS': '77ee4b39-3273-4671-b63b-ab6feb66eeb6', 'FWPM_CONDITION_EMBEDDED_REMOTE_PORT': 'cae4d6a1-2968-40ed-a4ce-547160dda88d', 'FWPM_CONDITION_ETHER_TYPE': 'fd08948d-a219-4d52-bb98-1a5540ee7b4e', 'FWPM_CONDITION_FLAGS': '632ce23b-5167-435c-86d7-e903684aa80c', 'FWPM_CONDITION_IMAGE_NAME': 'd024de4d-deaa-4317-9c85-e40ef6e140c3', 'FWPM_CONDITION_INTERFACE_INDEX': '667fd755-d695-434a-8af5-d3835a1259bc', 'FWPM_CONDITION_INTERFACE_MAC_ADDRESS': 'f6e63dce-1f4b-4c6b-b6ef-1165e71f8ee7', 'FWPM_CONDITION_INTERFACE_QUARANTINE_EPOCH': 'cce68d5e-053b-43a8-9a6f-33384c28e4f6', 'FWPM_CONDITION_INTERFACE_TYPE': 'daf8cd14-e09e-4c93-a5ae-c5c13b73ffca', 'FWPM_CONDITION_IPSEC_POLICY_KEY': 'ad37dee3-722f-45cc-a4e3-068048124452', 'FWPM_CONDITION_IPSEC_SECURITY_REALM_ID': '37a57700-5884-4964-92b8-3e704688b0ad', 'FWPM_CONDITION_IP_ARRIVAL_INTERFACE': '618a9b6d-386b-4136-ad6e-b51587cfb1cd', 'FWPM_CONDITION_IP_DESTINATION_ADDRESS': '2d79133b-b390-45c6-8699-acaceaafed33', 'FWPM_CONDITION_IP_DESTINATION_ADDRESS_TYPE': '1ec1b7c9-4eea-4f5e-b9ef-76beaaaf17ee', 'FWPM_CONDITION_IP_DESTINATION_PORT': 'ce6def45-60fb-4a7b-a304-af30a117000e', 'FWPM_CONDITION_IP_FORWARD_INTERFACE': '1076b8a5-6323-4c5e-9810-e8d3fc9e6136', 'FWPM_CONDITION_IP_LOCAL_ADDRESS': 'd9ee00de-c1ef-4617-bfe3-ffd8f5a08957', 'FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE': '6ec7f6c4-376b-45d7-9e9c-d337cedcd237', 'FWPM_CONDITION_IP_LOCAL_ADDRESS_V4': '03a629cb-6e52-49f8-9c41-5709633c09cf', 'FWPM_CONDITION_IP_LOCAL_ADDRESS_V6': '2381be84-7524-45b3-a05b-1e637d9c7a6a', 'FWPM_CONDITION_IP_LOCAL_INTERFACE': '4cd62a49-59c3-4969-b7f3-bda5d32890a4', 'FWPM_CONDITION_IP_LOCAL_PORT': '0c1ba1af-5765-453f-af22-a8f791ac775b', 'FWPM_CONDITION_IP_NEXTHOP_ADDRESS': 'eabe448a-a711-4d64-85b7-3f76b65299c7', 'FWPM_CONDITION_IP_NEXTHOP_INTERFACE': '93ae8f5b-7f6f-4719-98c8-14e97429ef04', 'FWPM_CONDITION_IP_PHYSICAL_ARRIVAL_INTERFACE': 'da50d5c8-fa0d-4c89-b032-6e62136d1e96', 'FWPM_CONDITION_IP_PHYSICAL_NEXTHOP_INTERFACE': 'f09bd5ce-5150-48be-b098-c25152fb1f92', 'FWPM_CONDITION_IP_PROTOCOL': '3971ef2b-623e-4f9a-8cb1-6e79b806b9a7', 'FWPM_CONDITION_IP_REMOTE_ADDRESS': 'b235ae9a-1d64-49b8-a44c-5ff3d9095045', 'FWPM_CONDITION_IP_REMOTE_ADDRESS_V4': '1febb610-3bcc-45e1-bc36-2e067e2cb186', 'FWPM_CONDITION_IP_REMOTE_ADDRESS_V6': '246e1d8c-8bee-4018-9b98-31d4582f3361', 'FWPM_CONDITION_IP_REMOTE_PORT': 'c35a604d-d22b-4e1a-91b4-68f674ee674b', 'FWPM_CONDITION_IP_SOURCE_ADDRESS': 'ae96897e-2e94-4bc9-b313-b27ee80e574d', 'FWPM_CONDITION_IP_SOURCE_PORT': 'a6afef91-3df4-4730-a214-f5426aebf821', 'FWPM_CONDITION_KM_AUTH_NAP_CONTEXT': '35d0ea0e-15ca-492b-900e-97fd46352cce', 'FWPM_CONDITION_KM_MODE': 'feef4582-ef8f-4f7b-858b-9077d122de47', 'FWPM_CONDITION_KM_TYPE': 'ff0f5f49-0ceb-481b-8638-1479791f3f2c', 'FWPM_CONDITION_L2_FLAGS': '7bc43cbf-37ba-45f1-b74a-82ff518eeb10', 'FWPM_CONDITION_LOCAL_INTERFACE_PROFILE_ID': '4ebf7562-9f18-4d06-9941-a7a625744d71', 'FWPM_CONDITION_MAC_DESTINATION_ADDRESS': '04ea2a93-858c-4027-b613-b43180c7859e', 'FWPM_CONDITION_MAC_DESTINATION_ADDRESS_TYPE': 'ae052932-ef42-4e99-b129-f3b3139e34f7', 'FWPM_CONDITION_MAC_LOCAL_ADDRESS': 'd999e981-7948-4c83-b742-c84e3b678f8f', 'FWPM_CONDITION_MAC_LOCAL_ADDRESS_TYPE': 'cc31355c-3073-4ffb-a14f-79415cb1ead1', 'FWPM_CONDITION_MAC_REMOTE_ADDRESS': '408f2ed4-3a70-4b4d-92a6-415ac20e2f12', 'FWPM_CONDITION_MAC_REMOTE_ADDRESS_TYPE': '027fedb4-f1c1-4030-b564-ee777fd867ea', 'FWPM_CONDITION_MAC_SOURCE_ADDRESS': '7b795451-f1f6-4d05-b7cb-21779d802336', 'FWPM_CONDITION_MAC_SOURCE_ADDRESS_TYPE': '5c1b72e4-299e-4437-a298-bc3f014b3dc2', 'FWPM_CONDITION_NDIS_MEDIA_TYPE': 'cb31cef1-791d-473b-89d1-61c5984304a0', 'FWPM_CONDITION_NDIS_PHYSICAL_MEDIA_TYPE': '34c79823-c229-44f2-b83c-74020882ae77', 'FWPM_CONDITION_NDIS_PORT': 'db7bb42b-2dac-4cd4-a59a-e0bdce1e6834', 'FWPM_CONDITION_NET_EVENT_TYPE': '206e9996-490e-40cf-b831-b38641eb6fcb', 'FWPM_CONDITION_NEXTHOP_INTERFACE_INDEX': '138e6888-7ab8-4d65-9ee8-0591bcf6a494', 'FWPM_CONDITION_NEXTHOP_INTERFACE_PROFILE_ID': 'd7ff9a56-cdaa-472b-84db-d23963c1d1bf', 'FWPM_CONDITION_NEXTHOP_INTERFACE_TYPE': '97537c6c-d9a3-4767-a381-e942675cd920', 'FWPM_CONDITION_NEXTHOP_SUB_INTERFACE_INDEX': 'ef8a6122-0577-45a7-9aaf-825fbeb4fb95', 'FWPM_CONDITION_NEXTHOP_TUNNEL_TYPE': '72b1a111-987b-4720-99dd-c7c576fa2d4c', 'FWPM_CONDITION_ORIGINAL_ICMP_TYPE': '076dfdbe-c56c-4f72-ae8a-2cfe7e5c8286', 'FWPM_CONDITION_ORIGINAL_PROFILE_ID': '46ea1551-2255-492b-8019-aabeee349f40', 'FWPM_CONDITION_PEER_NAME': '9b539082-eb90-4186-a6cc-de5b63235016', 'FWPM_CONDITION_PIPE': '1bd0741d-e3df-4e24-8634-762046eef6eb', 'FWPM_CONDITION_PROCESS_WITH_RPC_IF_UUID': 'e31180a8-bbbd-4d14-a65e-7157b06233bb', 'FWPM_CONDITION_QM_MODE': 'f64fc6d1-f9cb-43d2-8a5f-e13bc894f265', 'FWPM_CONDITION_REAUTHORIZE_REASON': '11205e8c-11ae-457a-8a44-477026dd764a', 'FWPM_CONDITION_REMOTE_ID': 'f68166fd-0682-4c89-b8f5-86436c7ef9b7', 'FWPM_CONDITION_REMOTE_USER_TOKEN': '9bf0ee66-06c9-41b9-84da-288cb43af51f', 'FWPM_CONDITION_RESERVED0': '678f4deb-45af-4882-93fe-19d4729d9834', 'FWPM_CONDITION_RESERVED1': 'd818f827-5c69-48eb-bf80-d86b17755f97', 'FWPM_CONDITION_RESERVED10': 'b979e282-d621-4c8c-b184-b105a61c36ce', 'FWPM_CONDITION_RESERVED11': '2d62ee4d-023d-411f-9582-43acbb795975', 'FWPM_CONDITION_RESERVED12': 'a3677c32-7e35-4ddc-93da-e8c33fc923c7', 'FWPM_CONDITION_RESERVED13': '335a3e90-84aa-42f5-9e6f-59309536a44c', 'FWPM_CONDITION_RESERVED14': '30e44da2-2f1a-4116-a559-f907de83604a', 'FWPM_CONDITION_RESERVED15': 'bab8340f-afe0-43d1-80d8-5ca456962de3', 'FWPM_CONDITION_RESERVED2': '53d4123d-e15b-4e84-b7a8-dce16f7b62d9', 'FWPM_CONDITION_RESERVED3': '7f6e8ca3-6606-4932-97c7-e1f20710af3b', 'FWPM_CONDITION_RESERVED4': '5f58e642-b937-495e-a94b-f6b051a49250', 'FWPM_CONDITION_RESERVED5': '9ba8f6cd-f77c-43e6-8847-11939dc5db5a', 'FWPM_CONDITION_RESERVED6': 'f13d84bd-59d5-44c4-8817-5ecdae1805bd', 'FWPM_CONDITION_RESERVED7': '65a0f930-45dd-4983-aa33-efc7b611af08', 'FWPM_CONDITION_RESERVED8': '4f424974-0c12-4816-9b47-9a547db39a32', 'FWPM_CONDITION_RESERVED9': 'ce78e10f-13ff-4c70-8643-36ad1879afa3', 'FWPM_CONDITION_RPC_AUTH_LEVEL': 'e5a0aed5-59ac-46ea-be05-a5f05ecf446e', 'FWPM_CONDITION_RPC_AUTH_TYPE': 'daba74ab-0d67-43e7-986e-75b84f82f594', 'FWPM_CONDITION_RPC_EP_FLAGS': '218b814a-0a39-49b8-8e71-c20c39c7dd2e', 'FWPM_CONDITION_RPC_EP_VALUE': 'dccea0b9-0886-4360-9c6a-ab043a24fba9', 'FWPM_CONDITION_RPC_IF_FLAG': '238a8a32-3199-467d-871c-272621ab3896', 'FWPM_CONDITION_RPC_IF_UUID': '7c9c7d9f-0075-4d35-a0d1-8311c4cf6af1', 'FWPM_CONDITION_RPC_IF_VERSION': 'eabfd9b7-1262-4a2e-adaa-5f96f6fe326d', 'FWPM_CONDITION_RPC_PROTOCOL': '2717bc74-3a35-4ce7-b7ef-c838fabdec45', 'FWPM_CONDITION_RPC_PROXY_AUTH_TYPE': '40953fe2-8565-4759-8488-1771b4b4b5db', 'FWPM_CONDITION_RPC_SERVER_NAME': 'b605a225-c3b3-48c7-9833-7aefa9527546', 'FWPM_CONDITION_RPC_SERVER_PORT': '8090f645-9ad5-4e3b-9f9f-8023ca097909', 'FWPM_CONDITION_SEC_ENCRYPT_ALGORITHM': '0d306ef0-e974-4f74-b5c7-591b0da7d562', 'FWPM_CONDITION_SEC_KEY_SIZE': '4772183b-ccf8-4aeb-bce1-c6c6161c8fe4', 'FWPM_CONDITION_SOURCE_INTERFACE_INDEX': '2311334d-c92d-45bf-9496-edf447820e2d', 'FWPM_CONDITION_SOURCE_SUB_INTERFACE_INDEX': '055edd9d-acd2-4361-8dab-f9525d97662f', 'FWPM_CONDITION_SUB_INTERFACE_INDEX': '0cd42473-d621-4be3-ae8c-72a348d283e1', 'FWPM_CONDITION_TUNNEL_TYPE': '77a40437-8779-4868-a261-f5a902f1c0cd', 'FWPM_CONDITION_VLAN_ID': '938eab21-3618-4e64-9ca5-2141ebda1ca2', 'FWPM_CONDITION_VSWITCH_DESTINATION_INTERFACE_ID': '8ed48be4-c926-49f6-a4f6-ef3030e3fc16', 'FWPM_CONDITION_VSWITCH_DESTINATION_INTERFACE_TYPE': 'fa9b3f06-2f1a-4c57-9e68-a7098b28dbfe', 'FWPM_CONDITION_VSWITCH_DESTINATION_VM_ID': '6106aace-4de1-4c84-9671-3637f8bcf731', 'FWPM_CONDITION_VSWITCH_ID': 'c4a414ba-437b-4de6-9946-d99c1b95b312', 'FWPM_CONDITION_VSWITCH_NETWORK_TYPE': '11d48b4b-e77a-40b4-9155-392c906c2608', 'FWPM_CONDITION_VSWITCH_SOURCE_INTERFACE_ID': '7f4ef24b-b2c1-4938-ba33-a1ecbed512ba', 'FWPM_CONDITION_VSWITCH_SOURCE_INTERFACE_TYPE': 'e6b040a2-edaf-4c36-908b-f2f58ae43807', 'FWPM_CONDITION_VSWITCH_SOURCE_VM_ID': '9c2a9ec2-9fc6-42bc-bdd8-406d4da0be64', 'FWPM_CONDITION_VSWITCH_TENANT_NETWORK_ID': 'dc04843c-79e6-4e44-a025-65b9bb0f9f94', 'FWPM_LAYER_ALE_AUTH_CONNECT_V4': 'c38d57d1-05a7-4c33-904f-7fbceee60e82', 'FWPM_LAYER_ALE_AUTH_CONNECT_V4_DISCARD': 'd632a801-f5ba-4ad6-96e3-607017d9836a', 'FWPM_LAYER_ALE_AUTH_CONNECT_V6': '4a72393b-319f-44bc-84c3-ba54dcb3b6b4', 'FWPM_LAYER_ALE_AUTH_CONNECT_V6_DISCARD': 'c97bc3b8-c9a3-4e33-8695-8e17aad4de09', 'FWPM_LAYER_ALE_AUTH_LISTEN_V4': '88bb5dad-76d7-4227-9c71-df0a3ed7be7e', 'FWPM_LAYER_ALE_AUTH_LISTEN_V4_DISCARD': '371dfada-9f26-45fd-b4eb-c29eb212893f', 'FWPM_LAYER_ALE_AUTH_LISTEN_V6': '7ac9de24-17dd-4814-b4bd-a9fbc95a321b', 'FWPM_LAYER_ALE_AUTH_LISTEN_V6_DISCARD': '60703b07-63c8-48e9-ada3-12b1af40a617', 'FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4': 'e1cd9fe7-f4b5-4273-96c0-592e487b8650', 'FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4_DISCARD': '9eeaa99b-bd22-4227-919f-0073c63357b1', 'FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6': 'a3b42c97-9f04-4672-b87e-cee9c483257f', 'FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6_DISCARD': '89455b97-dbe1-453f-a224-13da895af396', 'FWPM_LAYER_ALE_BIND_REDIRECT_V4': '66978cad-c704-42ac-86ac-7c1a231bd253', 'FWPM_LAYER_ALE_BIND_REDIRECT_V6': 'bef02c9c-606b-4536-8c26-1c2fc7b631d4', 'FWPM_LAYER_ALE_CONNECT_REDIRECT_V4': 'c6e63c8c-b784-4562-aa7d-0a67cfcaf9a3', 'FWPM_LAYER_ALE_CONNECT_REDIRECT_V6': '587e54a7-8046-42ba-a0aa-b716250fc7fd', 'FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4': 'b4766427-e2a2-467a-bd7e-dbcd1bd85a09', 'FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V6': 'bb536ccd-4755-4ba9-9ff7-f9edf8699c7b', 'FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4': 'af80470a-5596-4c13-9992-539e6fe57967', 'FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4_DISCARD': '146ae4a9-a1d2-4d43-a31a-4c42682b8e4f', 'FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6': '7021d2b3-dfa4-406e-afeb-6afaf7e70efd', 'FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6_DISCARD': '46928636-bbca-4b76-941d-0fa7f5d7d372', 'FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4': '1247d66d-0b60-4a15-8d44-7155d0f53a0c', 'FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4_DISCARD': '0b5812a2-c3ff-4eca-b88d-c79e20ac6322', 'FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6': '55a650e1-5f0a-4eca-a653-88f53b26aa8c', 'FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6_DISCARD': 'cbc998bb-c51f-4c1a-bb4f-9775fcacab2f', 'FWPM_LAYER_ALE_RESOURCE_RELEASE_V4': '74365cce-ccb0-401a-bfc1-b89934ad7e15', 'FWPM_LAYER_ALE_RESOURCE_RELEASE_V6': 'f4e5ce80-edcc-4e13-8a2f-b91454bb057b', 'FWPM_LAYER_DATAGRAM_DATA_V4': '3d08bf4e-45f6-4930-a922-417098e20027', 'FWPM_LAYER_DATAGRAM_DATA_V4_DISCARD': '18e330c6-7248-4e52-aaab-472ed67704fd', 'FWPM_LAYER_DATAGRAM_DATA_V6': 'fa45fe2f-3cba-4427-87fc-57b9a4b10d00', 'FWPM_LAYER_DATAGRAM_DATA_V6_DISCARD': '09d1dfe1-9b86-4a42-be9d-8c315b92a5d0', 'FWPM_LAYER_EGRESS_VSWITCH_ETHERNET': '86c872b0-76fa-4b79-93a4-0750530ae292', 'FWPM_LAYER_EGRESS_VSWITCH_TRANSPORT_V4': 'b92350b6-91f0-46b6-bdc4-871dfd4a7c98', 'FWPM_LAYER_EGRESS_VSWITCH_TRANSPORT_V6': '1b2def23-1881-40bd-82f4-4254e63141cb', 'FWPM_LAYER_IKEEXT_V4': 'b14b7bdb-dbbd-473e-bed4-8b4708d4f270', 'FWPM_LAYER_IKEEXT_V6': 'b64786b3-f687-4eb9-89d2-8ef32acdabe2', 'FWPM_LAYER_INBOUND_ICMP_ERROR_V4': '61499990-3cb6-4e84-b950-53b94b6964f3', 'FWPM_LAYER_INBOUND_ICMP_ERROR_V4_DISCARD': 'a6b17075-ebaf-4053-a4e7-213c8121ede5', 'FWPM_LAYER_INBOUND_ICMP_ERROR_V6': '65f9bdff-3b2d-4e5d-b8c6-c720651fe898', 'FWPM_LAYER_INBOUND_ICMP_ERROR_V6_DISCARD': 'a6e7ccc0-08fb-468d-a472-9771d5595e09', 'FWPM_LAYER_INBOUND_IPPACKET_V4': 'c86fd1bf-21cd-497e-a0bb-17425c885c58', 'FWPM_LAYER_INBOUND_IPPACKET_V4_DISCARD': 'b5a230d0-a8c0-44f2-916e-991b53ded1f7', 'FWPM_LAYER_INBOUND_IPPACKET_V6': 'f52032cb-991c-46e7-971d-2601459a91ca', 'FWPM_LAYER_INBOUND_IPPACKET_V6_DISCARD': 'bb24c279-93b4-47a2-83ad-ae1698b50885', 'FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET': 'effb7edb-0055-4f9a-a231-4ff8131ad191', 'FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE': 'd4220bd3-62ce-4f08-ae88-b56e8526df50', 'FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE_FAST': '853aaa8e-2b78-4d24-a804-36db08b29711', 'FWPM_LAYER_INBOUND_RESERVED2': 'f4fb8d55-c076-46d8-a2c7-6a4c722ca4ed', 'FWPM_LAYER_INBOUND_TRANSPORT_FAST': 'e41d2719-05c7-40f0-8983-ea8d17bbc2f6', 'FWPM_LAYER_INBOUND_TRANSPORT_V4': '5926dfc8-e3cf-4426-a283-dc393f5d0f9d', 'FWPM_LAYER_INBOUND_TRANSPORT_V4_DISCARD': 'ac4a9833-f69d-4648-b261-6dc84835ef39', 'FWPM_LAYER_INBOUND_TRANSPORT_V6': '634a869f-fc23-4b90-b0c1-bf620a36ae6f', 'FWPM_LAYER_INBOUND_TRANSPORT_V6_DISCARD': '2a6ff955-3b2b-49d2-9848-ad9d72dcaab7', 'FWPM_LAYER_INGRESS_VSWITCH_ETHERNET': '7d98577a-9a87-41ec-9718-7cf589c9f32d', 'FWPM_LAYER_INGRESS_VSWITCH_TRANSPORT_V4': 'b2696ff6-774f-4554-9f7d-3da3945f8e85', 'FWPM_LAYER_INGRESS_VSWITCH_TRANSPORT_V6': '5ee314fc-7d8a-47f4-b7e3-291a36da4e12', 'FWPM_LAYER_IPFORWARD_V4': 'a82acc24-4ee1-4ee1-b465-fd1d25cb10a4', 'FWPM_LAYER_IPFORWARD_V4_DISCARD': '9e9ea773-2fae-4210-8f17-34129ef369eb', 'FWPM_LAYER_IPFORWARD_V6': '7b964818-19c7-493a-b71f-832c3684d28c', 'FWPM_LAYER_IPFORWARD_V6_DISCARD': '31524a5d-1dfe-472f-bb93-518ee945d8a2', 'FWPM_LAYER_IPSEC_KM_DEMUX_V4': 'f02b1526-a459-4a51-b9e3-759de52b9d2c', 'FWPM_LAYER_IPSEC_KM_DEMUX_V6': '2f755cf6-2fd4-4e88-b3e4-a91bca495235', 'FWPM_LAYER_IPSEC_V4': 'eda65c74-610d-4bc5-948f-3c4f89556867', 'FWPM_LAYER_IPSEC_V6': '13c48442-8d87-4261-9a29-59d2abc348b4', 'FWPM_LAYER_KM_AUTHORIZATION': '4aa226e9-9020-45fb-956a-c0249d841195', 'FWPM_LAYER_NAME_RESOLUTION_CACHE_V4': '0c2aa681-905b-4ccd-a467-4dd811d07b7b', 'FWPM_LAYER_NAME_RESOLUTION_CACHE_V6': '92d592fa-6b01-434a-9dea-d1e96ea97da9', 'FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4': '41390100-564c-4b32-bc1d-718048354d7c', 'FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4_DISCARD': 'b3598d36-0561-4588-a6bf-e955e3f6264b', 'FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6': '7fb03b60-7b8d-4dfa-badd-980176fc4e12', 'FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6_DISCARD': '65f2e647-8d0c-4f47-b19b-33a4d3f1357c', 'FWPM_LAYER_OUTBOUND_IPPACKET_V4': '1e5c9fae-8a84-4135-a331-950b54229ecd', 'FWPM_LAYER_OUTBOUND_IPPACKET_V4_DISCARD': '08e4bcb5-b647-48f3-953c-e5ddbd03937e', 'FWPM_LAYER_OUTBOUND_IPPACKET_V6': 'a3b3ab6b-3564-488c-9117-f34e82142763', 'FWPM_LAYER_OUTBOUND_IPPACKET_V6_DISCARD': '9513d7c4-a934-49dc-91a7-6ccb80cc02e3', 'FWPM_LAYER_OUTBOUND_MAC_FRAME_ETHERNET': '694673bc-d6db-4870-adee-0acdbdb7f4b2', 'FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE': '94c44912-9d6f-4ebf-b995-05ab8a088d1b', 'FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE_FAST': '470df946-c962-486f-9446-8293cbc75eb8', 'FWPM_LAYER_OUTBOUND_TRANSPORT_FAST': '13ed4388-a070-4815-9935-7a9be6408b78', 'FWPM_LAYER_OUTBOUND_TRANSPORT_V4': '09e61aea-d214-46e2-9b21-b26b0b2f28c8', 'FWPM_LAYER_OUTBOUND_TRANSPORT_V4_DISCARD': 'c5f10551-bdb0-43d7-a313-50e211f4d68a', 'FWPM_LAYER_OUTBOUND_TRANSPORT_V6': 'e1735bde-013f-4655-b351-a49e15762df0', 'FWPM_LAYER_OUTBOUND_TRANSPORT_V6_DISCARD': 'f433df69-ccbd-482e-b9b2-57165658c3b3', 'FWPM_LAYER_RPC_EPMAP': '9247bc61-eb07-47ee-872c-bfd78bfd1616', 'FWPM_LAYER_RPC_EP_ADD': '618dffc7-c450-4943-95db-99b4c16a55d4', 'FWPM_LAYER_RPC_PROXY_CONN': '94a4b50b-ba5c-4f27-907a-229fac0c2a7a', 'FWPM_LAYER_RPC_PROXY_IF': 'f8a38615-e12c-41ac-98df-121ad981aade', 'FWPM_LAYER_RPC_UM': '75a89dda-95e4-40f3-adc7-7688a9c847e1', 'FWPM_LAYER_STREAM_PACKET_V4': 'af52d8ec-cb2d-44e5-ad92-f8dc38d2eb29', 'FWPM_LAYER_STREAM_PACKET_V6': '779a8ca3-f099-468f-b5d4-83535c461c02', 'FWPM_LAYER_STREAM_V4': '3b89653c-c170-49e4-b1cd-e0eeeee19a3e', 'FWPM_LAYER_STREAM_V4_DISCARD': '25c4c2c2-25ff-4352-82f9-c54a4a4726dc', 'FWPM_LAYER_STREAM_V6': '47c9137a-7ec4-46b3-b6e4-48e926b1eda4', 'FWPM_LAYER_STREAM_V6_DISCARD': '10a59fc7-b628-4c41-9eb8-cf37d55103cf', 'FWPM_CONDITION_SUBLAYER_INSPECTION': '877519e1-e6a9-41a5-81b4-8c4f118e4a60', 'FWPM_CONDITION_SUBLAYER_IPSEC_DOSP': 'e076d572-5d3d-48ef-802b-909eddb098bd', 'FWPM_CONDITION_SUBLAYER_IPSEC_FORWARD_OUTBOUND_TUNNEL': 'a5082e73-8f71-4559-8a9a-101cea04ef87', 'FWPM_CONDITION_SUBLAYER_IPSEC_SECURITY_REALM': '37a57701-5884-4964-92b8-3e704688b0ad', 'FWPM_CONDITION_SUBLAYER_IPSEC_TUNNEL': '83f299ed-9ff4-4967-aff4-c309f4dab827', 'FWPM_CONDITION_SUBLAYER_LIPS': '1b75c0ce-ff60-4711-a70f-b4958cc3b2d0', 'FWPM_CONDITION_SUBLAYER_RPC_AUDIT': '758c84f4-fb48-4de9-9aeb-3ed9551ab1fd', 'FWPM_CONDITION_SUBLAYER_SECURE_SOCKET': '15a66e17-3f3c-4f7b-aa6c-812aa613dd82', 'FWPM_CONDITION_SUBLAYER_TCP_CHIMNEY_OFFLOAD': '337608b9-b7d5-4d5f-82f9-3618618bc058', 'FWPM_CONDITION_SUBLAYER_TCP_TEMPLATES': '24421dcf-0ac5-4caa-9e14-50f6e3636af0', 'FWPM_CONDITION_SUBLAYER_TEREDO': 'ba69dc66-5176-4979-9c89-26a7b46a8327', 'FWPM_CONDITION_SUBLAYER_UNIVERSAL': 'eebecc03-ced4-4380-819a-2734397b2b74'}


class _PolicyError(ValueError):
    def __init__(self, code, status='FAIL'):
        self.status = status
        super().__init__(code)


def _pg(v):
    if isinstance(v, dict):
        if set(v) != {'Data1','Data2','Data3','Data4'}: raise _PolicyError('GUID_SCHEMA')
        for k,b in [('Data1',32),('Data2',16),('Data3',16)]: _pu(v[k],b)
        if not isinstance(v['Data4'],list) or len(v['Data4']) != 8: raise _PolicyError('GUID_BYTES')
        for n in v['Data4']: _pu(n,8)
        return guid(v)
    if not isinstance(v,str): raise _PolicyError('GUID_TYPE','INCONCLUSIVE')
    import re
    if not re.fullmatch(r'(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\})',v):
        raise _PolicyError('GUID_ENCODING','INCONCLUSIVE')
    return guid(v)


def _pu(v,b=64):
    if type(v) is not int or not 0 <= v < 2**b: raise _PolicyError('INTEGER_RANGE')
    return v


def _ps(v):
    if v in _POLICY_SYMBOLS: return _POLICY_SYMBOLS[v]
    return _pg(v)


def _px(x,path):
    found=x.findall(path)
    if not found: raise _PolicyError('MISSING:'+path,'INCONCLUSIVE')
    if len(found)!=1: raise _PolicyError('DUPLICATE:'+path)
    return found[0]


def _pt(x,path): return _px(x,path).text or ''


def _pi(x):
    if 'numItems' in x.attrib:
        if not x.attrib['numItems'].isdigit() or int(x.attrib['numItems']) != len(x.findall('item')): raise _PolicyError('COUNT:'+x.tag,'INCONCLUSIVE')
    return x.findall('item')


def _empty(x,path):
    e=_px(x,path)
    if list(e) or (e.text or '').strip(): raise _PolicyError('NONEMPTY:'+path)


def check_policy(bfe_xml, rules_json, *, guids_json=None):
    """Certify a snapshot against the supplied ledger and fixed twenty-rule template."""
    location='guids'
    try:
        if guids_json is None: raise _PolicyError('MISSING_LEDGER','INCONCLUSIVE')
        def parse(v): return json.loads(v,object_pairs_hook=unique,parse_constant=lambda v: (_ for _ in ()).throw(ValueError('nonfinite')))
        ledger=parse(guids_json)
        if not isinstance(ledger,list) or len(ledger)!=22 or any(not isinstance(g,str) for g in ledger): raise _PolicyError('LEDGER_SCHEMA','INCONCLUSIVE')
        ledger=[_pg(g) for g in ledger]
        if len(set(ledger))!=22 or str(uuid.UUID(int=0)) in ledger: raise _PolicyError('LEDGER_IDS')
        provider,sub=ledger[:2]; ids=set(ledger[2:])
        location='bfe'; root=ET.fromstring(bfe_xml)
        if root.tag!='wfpstate': raise _PolicyError('ROOT','INCONCLUSIVE')
        def owned(x,key):
            def ref(path):
                value=x.findtext(path,'')
                try: return _ps(value)
                except _PolicyError: return None
            return ref(key) in set(ledger) or ref('providerKey')==provider or ref('subLayerKey')==sub
        for inventory,key,want in [('providers','providerKey',provider),('subLayers','subLayerKey',sub)]:
            rows=[x for x in _pi(_px(root,inventory)) if owned(x,key)]
            if not rows: raise _PolicyError('MISSING:'+inventory,'INCONCLUSIVE')
            if len(rows)!=1 or _pg(_pt(rows[0],key))!=want: raise _PolicyError('INVENTORY:'+inventory)
            x=rows[0]; _empty(x,'flags'); _empty(x,'providerData')
            if inventory=='subLayers' and (_pg(_pt(x,'providerKey'))!=provider or _pt(x,'weight')!='65535'): raise _PolicyError('SUBLAYER')
        fields={_POLICY_SYMBOLS['FWPM_CONDITION_IP_'+n]:(n,b) for n,b in [('REMOTE_ADDRESS',32),('PROTOCOL',8),('LOCAL_PORT',16),('REMOTE_PORT',16)]}
        user=_POLICY_SYMBOLS["FWPM_CONDITION_ALE_USER_ID"]
        fields[user]=("ALE_USER_ID",0)
        def conditions(rows,xml=False):
            out=[]
            for c in rows:
                f=_ps(_pt(c,'fieldKey')) if xml else _pg(c['Field'])
                if f not in fields: raise _PolicyError('FIELD_UNKNOWN','INCONCLUSIVE')
                name,b=fields[f]
                if ( _pt(c,'matchType')!='FWP_MATCH_EQUAL' if xml else type(c['Op']) is not int or c['Op']!=0): raise _PolicyError('CONDITION_OPERATOR')
                if name=="ALE_USER_ID":
                    v=c1_sd.bfe(_px(c,"conditionValue")) if xml else c1_sd.native(c["Value"])
                    out.append((f,v))
                    continue
                if xml:
                    cv=_px(c,'conditionValue')
                    if _pt(cv,'type')!='FWP_UINT'+str(b): raise _PolicyError('CONDITION_TYPE')
                    if len(cv)!=2: raise _PolicyError('CONDITION_ENCODING')
                    v=_pt(cv,'uint'+str(b))
                    if name!='REMOTE_ADDRESS': v=int(v)
                else: v=c['Value']
                if name=='REMOTE_ADDRESS':
                    import ipaddress
                    if not isinstance(v,str) or str(ipaddress.IPv4Address(v))!=v: raise _PolicyError('IP_ENCODING','INCONCLUSIVE')
                else: _pu(v,b)
                out.append((f,v))
            if len({f for f,v in out})!=len(out): raise _PolicyError('DUPLICATE_CONDITION')
            return tuple(sorted(out))
        def canonical(i,k,p,s,l,a,w,c):
            if p!=provider or s!=sub: raise _PolicyError('OWNERSHIP')
            if not _pu(k): raise _PolicyError('KERNEL_ID_ZERO')
            return (i,k,p,s,l,a,_pu(w),c)
        go={}; kernels=set(); location='rules'
        rules=parse(rules_json)
        if not isinstance(rules,list): raise _PolicyError('RULES_SCHEMA','INCONCLUSIVE')
        for index,r in enumerate(rules):
            location='rules/'+str(index)
            i=_pg(r['ID']); p=_pg(r['Provider']); s=_pg(r['Sublayer'])
            if i not in ids and p!=provider and s!=sub: continue
            if i not in ids or i in go: raise _PolicyError('EXTRA_OR_DUPLICATE_ID')
            for flag in ['Disabled','HardAction','Persistent','BootTime','PermitIfMissing']:
                if r[flag] is not False: raise _PolicyError('FLAG:'+flag)
            if r['ProviderData'] not in (None,'',[]) or _pg(r['Callout'])!=str(uuid.UUID(int=0)): raise _PolicyError('GO_CONTEXT')
            if type(r['Action']) is not int or r['Action'] not in (4097,4098): raise _PolicyError('ACTION')
            rec=canonical(i,r['KernelID'],p,s,_pg(r['Layer']),{4097:'BLOCK',4098:'PERMIT'}[r['Action']],r['Weight'],conditions(r['Conditions'] or []))
            if rec[1] in kernels: raise _PolicyError('KERNEL_COLLISION')
            kernels.add(rec[1]); go[i]=rec
        bfe={}; kernels=set(); location='bfe/layers'
        for layer in _pi(_px(root,'layers')):
            for x in _pi(_px(layer,'filters')):
                if not owned(x,'filterKey'): continue
                i=_pg(_pt(x,'filterKey')); location='bfe/filter/'+i
                if i not in ids or i in bfe: raise _PolicyError('EXTRA_OR_DUPLICATE_ID')
                # Duplicate scalar/container nodes are never silently selected.
                for e in x.iter():
                    tags=[c.tag for c in e if c.tag!='item']
                    if len(tags)!=len(set(tags)): raise _PolicyError('DUPLICATE_XML:'+e.tag)
                    _pi(e)
                l=_ps(_pt(x,'layerKey'))
                if l!=_ps(_pt(layer,'layer/layerKey')): raise _PolicyError('CONTAINING_LAYER')
                flags=_px(x,'flags')
                if (flags.text or '').strip() or any(c.tag!='item' or c.text!='FWPM_FILTER_FLAG_INDEXED' for c in flags) or len(flags)>1: raise _PolicyError('FILTER_FLAGS')
                _empty(x,'providerData'); _empty(x,'action/filterType')
                if _pt(x,'rawContext')!='0': raise _PolicyError('RAW_CONTEXT')
                weights=[]
                for key in ['weight','effectiveWeight']:
                    e=_px(x,key)
                    if _pt(e,'type')!='FWP_UINT64' or len(e)!=2: raise _PolicyError('WEIGHT_TYPE:'+key)
                    weights.append(_pu(int(_pt(e,'uint64'))))
                if weights[0]!=weights[1]: raise _PolicyError('EFFECTIVE_WEIGHT')
                a=_pt(x,'action/type')
                if a not in ('FWP_ACTION_BLOCK','FWP_ACTION_PERMIT'): raise _PolicyError('ACTION')
                rec=canonical(i,int(_pt(x,'filterId')),_pg(_pt(x,'providerKey')),_pg(_pt(x,'subLayerKey')),l,a.removeprefix('FWP_ACTION_'),weights[0],conditions(_pi(_px(x,'filterCondition')),True))
                if rec[1] in kernels: raise _PolicyError('KERNEL_COLLISION')
                kernels.add(rec[1]); bfe[i]=rec
        for i in ids & go.keys() & bfe.keys():
            if go[i]!=bfe[i]: raise _PolicyError('READBACK_MISMATCH:'+i)
        if set(go)!=ids or set(bfe)!=ids: raise _PolicyError('MISSING_FILTER','INCONCLUSIVE')
        from collections import Counter
        expected=[]
        remote=_POLICY_SYMBOLS['FWPM_CONDITION_IP_REMOTE_ADDRESS']; proto=_POLICY_SYMBOLS['FWPM_CONDITION_IP_PROTOCOL']
        for family in ['ALE_AUTH_CONNECT','ALE_AUTH_RECV_ACCEPT','OUTBOUND_TRANSPORT','INBOUND_TRANSPORT']:
            for version in [4,6]:
                l=_POLICY_SYMBOLS['FWPM_LAYER_'+family+'_V'+str(version)]; expected.append((l,'BLOCK',1,()))
                if version==4:
                    for port in [500,4500,None]:
                        c=[(remote,'<LAB_PUBLIC_IP>'),(proto,17 if port else 50)]
                        if port: c += [(_POLICY_SYMBOLS['FWPM_CONDITION_IP_'+n],port) for n in ['LOCAL_PORT','REMOTE_PORT']]
                        if family.startswith('ALE_'): c.append((user,c1_sd.CANONICAL))
                        expected.append((l,'PERMIT',800,tuple(sorted(c))))
        if Counter(r[4:] for r in go.values())!=Counter(expected): raise _PolicyError('TEMPLATE')
        return result('PASS',[],evidence={'filters':list(go.values()),'scope':'snapshot'})
    except _PolicyError as exc:
        return result(exc.status,[str(exc)+':'+location],evidence={})
    except (ValueError,TypeError,KeyError,AttributeError,ET.ParseError,OverflowError) as exc:
        return result('INCONCLUSIVE',['POLICY_ENCODING:'+location+':'+type(exc).__name__],evidence={})


def evidence(pcap, nonce, journal, pin, start, end):
    parsed = assess(pcap, nonce, str(start), str(end))
    log = snapshot(journal, nonce, pin['producer'])
    if log['partialBytes']: raise ValueError('Partial journal')
    flows = pin['flows']
    if set(flows) != TARGETS: raise ValueError('All 12 pinned flows required')
    attempts = {(str(r['round']), r['target']) for r in log['records'] if r['kind'] == 'attempt'}
    hits = []
    for packet in parsed['records']:
        for target, flow in flows.items():
            if all(packet[k] == flow[k] for k in ('src','dst','protocol','sport','dport')):
                for rnd in packet['rounds']:
                    if (rnd, target) in attempts: hits.append(dict(packet=packet, target=target, round=rnd))
    return parsed, log, hits


def check_controls(pcap, nonce, journal, pin):
    try:
        parsed, log, hits = evidence(pcap, nonce, journal, pin, pin['controlStart'], pin['wfpEarliest'])
        seen = {h['target'] for h in hits if h['packet']['phase'] == 'inside'}
        opened = {r['target'] for r in log['records'] if r['kind']=='tcp-open' and r['status']=='ok'}
        missing = TARGETS-seen
        reasons = []
        if missing: reasons.append('Missing external controls: '+','.join(sorted(missing)))
        if not {t for t in TARGETS if t.startswith('tcp/')} <= opened: reasons.append('Preexisting TCP opens unproved')
        for port in (500,4500):
            f = pin['flows'][f'carrier/<LAB_PUBLIC_IP>/{port}']
            if f['sport'] != port or f['dport'] != port: reasons.append('Carrier ports mismatch')
        if parsed['limitations']: reasons.append('Capture parser limitations')
        # Exact external packets are established, but process attribution is separate.
        return result('INCONCLUSIVE' if reasons else 'CONTROLS_OBSERVED', reasons, observed=sorted(seen))
    except (ValueError, TypeError, KeyError) as exc:
        return result('INCONCLUSIVE', [str(exc)])


def assess_interval(samples, pcap, journal, nonce, pin, start, end):
    try:
        parsed, log, hits = evidence(pcap, nonce, journal, pin, start, end)
        escapes = [h for h in hits if h['packet']['phase']=='inside']
        if escapes:
            return result('FAIL', ['Correlated ordinary challenge escaped, including permitted endpoint carriers'], escapes=escapes)
        reasons = ['Continuous identity, health, clock mapping and attempt coverage certification is not implemented; quiet capture cannot establish safety']
        if Decimal(str(end))-Decimal(str(start)) < 300: reasons.append('Interval shorter than 300 seconds')
        if parsed['limitations']: reasons.append('Capture parser limitations')
        return result('INCONCLUSIVE', reasons, escapes=[])
    except (ValueError, TypeError, KeyError) as exc:
        return result('INCONCLUSIVE', [str(exc)], escapes=[])


# Integration validators consume frozen raw bytes. No caller boolean grants authority.
from protected_transport import strict as _json, sha as _hash
import re as _re
import ipaddress as _ip

def _need(condition, message):
    if not condition: raise ValueError(message)

def _pin(raw, nonce):
    p=_json(raw);_need(p['nonce']==nonce and len(p['process'])==2,'Original producer pin')
    _need(len({x['pid'] for x in p['process']})==2,'Distinct producer pins')
    ps=next(x for x in p['process'] if x['pid']==p['producer']['pid'])
    _need(all(ps[k]==p['producer'][k] for k in ('pid','start','sid')),'Journal process identity')
    for x in p['process']:
        _need(x['alive'] is True and x['elevated'] is False and x['integrity']=='S-1-16-8192' and x['sid']==p['registration']['principal']['sid'],'Ordinary process token')
        _need(_re.fullmatch('[a-fA-F0-9]{64}',x['sha256']) is not None,'Pinned image digest')
    parent=next(x for x in p['process'] if x['pid']!=ps['pid'])
    _need(ps['parent']==parent['pid']==p['launch']['engine']==p['event200']['engine'],'Task process chain')
    _need(p['event200']['guid']==p['launch']['guid'] and p['event200']['record']>p['launch']['bookmark'],'Task event binding')
    return p

def _causal_hits(pcap,journal,nonce,pin,cutoff=None):
    try:
        log=snapshot(journal,nonce,pin['producer']);_need(not log['partialBytes'],'Partial journal')
    except (ValueError,KeyError,TypeError):
        if cutoff is None: raise
        # A later malformed record cannot erase a proved earlier complete round.
        boundaries=[m.end() for m in _re.finditer(b'\n',journal)]
        lo,hi=0,len(boundaries)
        while lo<hi:
            middle=(lo+hi+1)//2
            try:snapshot(journal[:boundaries[middle-1]],nonce,pin['producer']);lo=middle
            except (ValueError,KeyError,TypeError):hi=middle-1
        _need(lo>0,'No valid causal prefix')
        log=snapshot(journal[:boundaries[lo-1]],nonce,pin['producer'])
    packets=assess(pcap,nonce,'0','999999999999')['records']
    attempts={(r['round'],r['target']):r for r in log['records'] if r['kind']=='attempt'}
    complete={r['round'] for r in log['rounds']}
    from preexisting import exact_hits
    hits=exact_hits(dict(records=packets),log['records'],nonce,cutoff)
    for r in log['records']:
        if r['target'].startswith('carrier/'): continue
        if r['kind']!='result' or r['round'] not in complete: continue
        a=attempts[(r['round'],r['target'])]
        if cutoff and (r['round']<=cutoff['round'] or a['sequence']<=cutoff['sequence']):continue
        m=_re.fullmatch(r'sent(?::([0-9]+))? local=(\[[^\]]+\]|[^:]+):([0-9]+)',r['status'])
        if not m:continue
        proto,dst,port=r['target'].split('/');src=str(_ip.ip_address(m[2].strip('[]')));sport=int(m[3]);port=int(port)
        if proto=='tcp':_need(a['status']=='preexisting-send','Preexisting TCP operation')
        for packet in packets:
            if (packet['src'],packet['dst'],packet['protocol'],packet['sport'],packet['dport'])!=(src,dst,6 if proto=='tcp' else 17,sport,port):continue
            if packet['rounds']!=[str(r['round'])]:continue
            payload=('STEP10-'+nonce+'-ROUND-'+str(r['round'])+'-END').encode()
            if port==53:
                payload=bytes.fromhex('531001000001000000000000')
                for label in ('s10',nonce[:32],nonce[32:],'r'+str(r['round']),'test'):
                    b=label.encode();payload+=bytes([len(b)])+b
                payload+=bytes.fromhex('0000010001')
                if proto=='tcp':payload=len(payload).to_bytes(2,'big')+payload
            if packet['payloadHex']!=payload.hex():continue
            hits.append(dict(packet=packet,target=r['target'],round=r['round'],attemptSequence=a['sequence'],resultSequence=r['sequence'],captureSHA256=_hash(pcap),journalSHA256=_hash(journal)))
    return log,hits

def _healthy(collection):
    from persistent import stamp
    h=collection['readiness']
    _need(h['ready'] is True and h['healthy'] is True and h['failure'] is None,'Inspector readiness')
    _need(0<=collection['clock']['utc']-stamp(h['utc'])<=6,'Stale inspector health')

def check_causal_admission(controls,preflight,ready,nonce):
    try:
        p=_pin(controls['files']['original-producer-pin.json'],nonce)
        _need(preflight['nonce']==nonce and _json(preflight['once'])['configSHA256']==preflight['configSHA256'],'Preflight binding')
        expected=_json(controls['files']['expected.json'])
        _need(expected['nonce']==nonce and expected['registration']==p['registration'] and expected['inputs']==p['inputs'],'Expected producer registration/inputs')
        _need(any(x['role']=='probe.ps1' and x['sha256'].lower()==preflight['probeSHA256'] for x in p['inputs']),'Reviewed producer socket code digest')
        for process in p['process']:
            image=expected['images']['powershell' if process['pid']==p['producer']['pid'] else 'cmd']
            _need(process['path'].lower()==image['path'].lower() and process['sha256'].lower()==image['sha256'].lower() and process['arguments']==image['arguments'],'Expected image/arguments')
        _need(sorted(controls['exactPorts'],key=lambda x:x['port'])==[dict(address='192.0.2.2',port=port,pid=p['producer']['pid']) for port in (500,4500)],'Exact ports must belong to retained producer')
        _healthy(controls)
        for role in ('supervisor','collector','barrier'):
            r=_json(ready['files']['reader-'+role+'-ready.json'])
            _need(r['nonce']==nonce and r['role']==role and r['producer']==p['producer'] and r['noHandle'] is False and r['ready'] and r['opened'] and not r['failure'],'Reader admission')
        log,hits=_causal_hits(controls['pcap'],controls['journal'],nonce,p)
        opened={r['target'] for r in log['records'] if r['kind']=='tcp-open' and r['status']=='connected'}
        _need({t for t in TARGETS if t.startswith('tcp/')}<=opened,'Four connected preexisting TCP flows')
        _need({h['target'] for h in hits}==TARGETS,'All12 causal controls')
        from preexisting import EXACT, continuity
        _need(continuity(log['records'],nonce) is None,'Early challenge')
        for target in EXACT:
            _need(len({h['round'] for h in hits if h['target']==target and h['round'] in {r['round'] for r in log['rounds']}})>=3,'Three external PRE rounds per retained socket')
        return dict(schema='full300-admission-v1',admitted=True,status='PASS',reasons=[],controls=hits)
    except (ValueError,KeyError,TypeError,StopIteration) as e:
        return dict(schema='full300-admission-v1',admitted=False,status='INCONCLUSIVE',reasons=[str(e)])

def check_start_lifecycle(policy,ready,binding):
    try:
        v=policy['collection'];p=_pin(v['files']['original-producer-pin.json'],binding['Nonce'])
        log=snapshot(v['journal'],binding['Nonce'],p['producer'])
        # Producer publishes its own timer origin/frequency; never use guest wall time.
        timer=_json(log['records'][0]['status'])
        elapsed=(log['records'][-1]['ticks']-timer['origin'])/timer['frequency']
        _need(timer['seconds']==900 and timer['frequency']>0 and 0<=elapsed<=540,'Producer remaining budget below 360 seconds')
        _healthy(v)
        _need(policy['response']['owner']['handleState']=='live','Original owner not live')
        return result('PASS',[])
    except (ValueError,KeyError,TypeError) as e:return result('INCONCLUSIVE',[str(e)])

def check_start_ack(ack,binding):
    try:
        s=_json(ack['native_status']);events=[_json(x) for x in ack['native_events'].splitlines()]
        _need(all(s[k]==v for k,v in binding.items()) and s['State']=='OBSERVING' and not s['Errors'],'Native start status')
        _need(sum(e['Event']=='observation started' for e in events)==1 and not any(e['Event']=='closed' for e in events),'Native start events')
        _need(ack['response']['owner']['sha256']==binding['SHA256'] and ack['response']['owner']['handleState']=='live' and ack['relay']['outcome']=='accepted','Original supervisor acknowledgement')
        return result('PASS',[])
    except (ValueError,KeyError,TypeError) as e:return result('INCONCLUSIVE',[str(e)])

def check_observation_lifecycle(interval,binding,operational=True):
    try:
        if operational:_healthy(interval)
        s=_json(interval['native_status_bytes'])
        _need(s==interval['native_status'] and all(s[k]==v for k,v in binding.items()),'Native status binding')
        _need(s['State']=='OBSERVING' and not s['Errors'] and interval['response']['owner']['handleState']=='live','Owner lifecycle lost')
        _need(check_start_ack(interval['start_ack'],binding)['status']=='PASS','Start provenance lost')
        _need(all(interval['response']['owner'][k]==interval['start_ack']['response']['owner'][k] for k in ('pid','creationFileTime','path','sha256')),'Original owner replaced')
        events=[_json(x) for x in interval['native_events'].splitlines()]
        _need(not any(e['Event']=='closed' for e in events),'Owner closed before capture')
        return result('PASS',[])
    except (ValueError,KeyError,TypeError) as e:return result('INCONCLUSIVE',[str(e)])

def assess_causal_escape(interval,controls,binding,cutoff,prefix):
    try:
        _need(interval['journal'].startswith(prefix),'Journal rewritten after fence')
        _need(check_observation_lifecycle(interval,binding,operational=False)['status']=='PASS','Unproved active owner lifecycle')
        p=_pin(controls['files']['original-producer-pin.json'],binding['Nonce'])
        log,hits=_causal_hits(interval['pcap'],interval['journal'],binding['Nonce'],p,cutoff)
        if hits:return result('FAIL',['CAUSAL_ORDINARY_ESCAPE'],escapes=hits)
        return result('INCONCLUSIVE',['CLOCK_BOUND_UNPROVEN'],escapes=[])
    except (ValueError,KeyError,TypeError) as e:return result('INCONCLUSIVE',[str(e),'CLOCK_BOUND_UNPROVEN'],escapes=[])

def check_early_preparation(bundle, nonce):
    """Executed pre-deployment seal, never an absence-of-inspector exemption.

    Source/start bytes are supplied by the controller that retains the original
    Popen. The preparation invocation seals this branch in finally and cannot
    resume admission. No guest inspector receipt is invented for it.
    """
    import base64
    d = _json(bundle['wrapper'])
    _need(set(d) == {'schema','nonce'} and d == dict(schema='full300-early-drain-v1', nonce=nonce), 'Early drain schema')
    p = _json(bundle['early'])
    _need(set(p) == {'schema','nonce','sourceSHA256','host','session','stage','sealed',
                    'deploymentAttempted','wrapperMutationAttempted','inspectorLaunchAttempted',
                    'inspectorJob','controlSession','baseline','current'}, 'Early preparation fields')
    _need(p['schema'] == 'full300-early-preparation-v1' and p['nonce'] == nonce
          and p['stage'] == 'baseline-captured' and p['sealed'] is True, 'Executed early seal')
    _need(all(p[k] is False for k in ('deploymentAttempted','wrapperMutationAttempted','inspectorLaunchAttempted'))
          and p['inspectorJob'] is None and p['controlSession'] is None, 'Early stage crossed launch boundary')
    start = _json(bundle['start'])
    _need(set(start) == {'schema','nonce','sourceSHA256','commandSHA256','pid','creationFileTime'}
          and start['schema'] == 'full300-preparation-start-v1' and start['nonce'] == nonce, 'Original preparation start')
    _need(start['sourceSHA256'] == p['sourceSHA256'] == _hash(bundle['source'])
          and re.fullmatch('[a-f0-9]{64}', start['commandSHA256']) is not None, 'Executed preparation source binding')
    _need(set(p['host']) == {'pid','creationFileTime'} and type(start['pid']) is int and start['pid'] > 0
          and isinstance(start['creationFileTime'], str) and re.fullmatch('[1-9][0-9]*', start['creationFileTime'])
          and p['host'] == {k:start[k] for k in ('pid','creationFileTime')}, 'Original preparation identity')
    s = p['session']
    _need(set(s) == {'instanceId','state','availability'} and s['state'] == 'Opened'
          and s['availability'] == 'Available' and isinstance(s['instanceId'],str)
          and str(uuid.UUID(s['instanceId'])) == s['instanceId'], 'Retained idle preparation session')
    a = _json(bundle['admissions']); c = _json(bundle['closures'])
    _need(a == dict(schema='full300-reader-admissions-v1', nonce=nonce, sealed=True, entries=[])
          and a['sealed'] is True, 'Early drain requires sealed zero reader admissions')
    _need(c == dict(bundle=dict(schema='full300-reader-closures-v1', nonce=nonce,
                 admissionsSHA256=_hash(bundle['admissions']), entries=[]), artifacts={}), 'Empty reader closure binding')
    _need(bundle['files'] == {}, 'Early drain cannot contain inspector/producer evidence')
    states = [_json(base64.b64decode(p[k], validate=True)) for k in ('baseline','current')]
    for state in states:
        _need(set(state) == {'schema','nonce','task','wrapper','policy'}
              and state['schema'] == 'full300-early-state-v1' and state['nonce'] == nonce, 'Early raw state fields')
        t = state['task']
        _need(set(t) == {'path','xml','security','state','instanceGuids'} and t['path'] == '\\BimeronStep8Probe'
              and type(t['state']) is int and t['state'] == 3 and t['instanceGuids'] == [], 'Exact idle ordinary task')
        _need(isinstance(t['xml'],str) and bool(t['xml']) and isinstance(t['security'],str) and bool(t['security']), 'Original task bytes required')
        _need(bool(base64.b64decode(state['wrapper'],validate=True)), 'Original wrapper bytes required')
        policy = _json(base64.b64decode(state['policy'],validate=True))
        _need(isinstance(policy,list) and len(policy) == 5
              and all(set(x) == {'Scope','ExecutionPolicy'} for x in policy)
              and all(type(x['Scope']) is int and type(x['ExecutionPolicy']) is int for x in policy)
              and {x['Scope'] for x in policy} == set(range(5)), 'Complete policy baseline required')
    _need(states[0] == states[1], 'Early task/wrapper/policy changed')
    return result('PASS', [], refs=dict(readerClosure=_hash(bundle['closures']), taskClosure=_hash(bundle['early'])))


def check_early_preparation_exit(bundle, nonce):
    try:
        check_early_preparation(bundle, nonce)
        p = _json(bundle['early']); release = _json(bundle['release'])
        _need(release == dict(schema='full300-preparation-release-v1', nonce=nonce,
              earlySHA256=_hash(bundle['early']), cleanupSHA256=_hash(bundle['cleanup'])), 'Explicit early release binding')
        cleanup = _json(bundle['cleanup'])
        _need(cleanup['nonce'] == nonce and all(cleanup[k] is True for k in ('rasAbsent','ownerAbsent','taskReady')),
              'Protected cleanup before session release')
        c = _json(bundle['closed'])
        _need(set(c) == {'schema','nonce','host','sessionId','stateBefore','availabilityBefore','stateAfter','releaseSHA256'}
              and c['schema'] == 'full300-preparation-session-closed-v1' and c['nonce'] == nonce,
              'Preparation session closure schema')
        _need(c['host'] == p['host'] and c['sessionId'] == p['session']['instanceId']
              and c['stateBefore'] == 'Opened' and c['availabilityBefore'] == 'Available'
              and c['stateAfter'] == 'Closed' and c['releaseSHA256'] == _hash(bundle['release']),
              'Retained original session closure')
        return result('PASS', [])
    except (ValueError,KeyError,TypeError) as e: return result('INCONCLUSIVE', [str(e)])


def check_exact_drain(bundle,nonce):
    try:
        d=_json(bundle['wrapper']);files=bundle['files']
        if d.get('schema') == 'full300-early-drain-v1':
            return check_early_preparation(bundle, nonce)
        if d.get('schema')=='full300-prelaunch-drain-v1':
            _need(set(d)=={'schema','nonce'} and d['nonce']==nonce,'Prelaunch drain binding')
            a=_json(bundle['admissions']);task=_json(bundle['task']);final=_json(files['inspector-final.json']);exited=_json(files['inspector-exit-proof.json']);expected=_json(files['expected.json'])
            _need(a['nonce']==nonce and a['sealed'] is True and a['entries']==[],'No reader admission required for unpinned prelaunch closure')
            _need(final['nonce']==nonce and final['launchNeverOccurred'] is True and final['launch'] is None and final['processes']==[],'Inspector never launched producer')
            _need(exited['nonce']==nonce and exited['waitResult']=='signalled' and exited['inspectorFinalSHA256']==_hash(files['inspector-final.json']) and exited['expectedSHA256']==_hash(files['expected.json']),'Original inspector exit')
            _need(task['nonce']==nonce and task['state']==3 and task['instanceGuids']==[] and _json(files['registration.json'])==expected['registration'],'Unlaunched task exact registration')
            return result('PASS',[],refs=dict(readerClosure=_hash(bundle['admissions']),taskClosure=_hash(bundle['task'])))
        def raw(ref):
            _need(set(ref)=={'name','sha256','length'},'Ref schema')
            b=files[ref['name']];_need(len(b)==ref['length'] and _hash(b)==ref['sha256'],'Drain reference mismatch');return b
        def obj(ref):return _json(raw(ref))
        _need(set(d)=={'schema','nonce','configSHA256','binding','admissions','readerClosures','taskClosure','inspectorExit','inspectorFinal','producerPin','terminalJournal','stopRequest'} and d['schema']=='full300-drain-v1' and d['nonce']==nonce,'Drain schema')
        a=obj(d['admissions']);c=obj(d['readerClosures']);t=obj(d['taskClosure'])
        _need(set(a)=={'schema','nonce','sealed','entries'} and set(c)=={'schema','nonce','admissionsSHA256','entries'},'Reader wrapper fields')
        _need(set(t)=={'schema','nonce','expected','launch','producerPin','inspectorFinal','inspectorExit','taskReadback','terminalJournal','stopRequest'},'Task closure fields')
        pin=_pin(raw(d['producerPin']),nonce)
        _need(a['schema']=='full300-reader-admissions-v1' and a['nonce']==nonce and a['sealed'] is True,'Admission seal')
        _need(c['schema']=='full300-reader-closures-v1' and c['nonce']==nonce and c['admissionsSHA256']==d['admissions']['sha256'],'Closure admission binding')
        roles=[x['role'] for x in a['entries']];_need(len(set(roles))==len(roles) and set(roles)<= {'supervisor','collector','barrier'},'Admission roles')
        _need({x['role'] for x in c['entries']}==set(roles) and len(c['entries'])==len(roles),'All admitted readers must close')
        for entry in a['entries']:
            _need(set(entry)=={'role','sessionOpen','transportReceipt'},'Admission entry fields')
            started=obj(entry['transportReceipt']);closed_entry=next(x for x in c['entries'] if x['role']==entry['role']);exited=obj(closed_entry['transportExit']);closed=obj(closed_entry['closed'])
            fields={'schema','nonce','role','requestId','pid','creationFileTime','commandSHA256','state','exitCode','response'}
            _need(set(started)==fields and set(exited)==fields and set(closed_entry)=={'role','closed','transportExit'},'Transport receipt fields')
            for k in ('schema','nonce','role','requestId','pid','creationFileTime','commandSHA256'):_need(started[k]==exited[k],'Original transport identity')
            _need(started['schema']=='full300-local-transport-v1' and started['state']=='started' and exited['state']=='signalled' and type(exited['exitCode']) is int and started['creationFileTime'] is not None,'Retained controller exit')
            _need(closed['nonce']==nonce and closed['role']==entry['role'] and closed['closed'] and type(closed['noHandle']) is bool,'Reader closure')
            _need(closed['noHandle'] or closed['opened'],'Reader handle closure provenance')
            if closed.get('cancelled'):
                _need(d['stopRequest'] is not None and closed['requestId']==obj(d['stopRequest'])['requestId'],'Reader cancellation request mismatch')
            _need(raw(exited['response'])==raw(closed_entry['closed']),'Returned reader differs from closure')
        final=obj(d['inspectorFinal']);exit=obj(d['inspectorExit'])
        _need(set(exit)=={'schema','nonce','expectedSHA256','inspector','waitResult','exitCode','inspectorFinalSHA256'},'Inspector exit fields')
        _need(exit['schema']=='full300-inspector-exit-v1' and exit['nonce']==nonce and exit['waitResult']=='signalled' and exit['inspectorFinalSHA256']==d['inspectorFinal']['sha256'],'Retained inspector exit')
        _need(final['nonce']==nonce and final['exitVerified'] is True and final['taskClosureVerified'] is True,'Inspector retained producer closure')
        _need({(x['pid'],x['start']) for x in final['processes']}=={(x['pid'],x['start']) for x in pin['process']} and all(x['alive'] is False for x in final['processes']),'Both original producer waits')
        _need(t['schema']=='full300-task-closure-v1' and t['nonce']==nonce,'Task closure schema')
        for k in ('producerPin','inspectorFinal','inspectorExit','terminalJournal','stopRequest'):_need(t[k]==d[k],'Task transitive mismatch')
        expected=obj(t['expected']);launch=obj(t['launch']);task=obj(t['taskReadback'])
        _need(set(task)=={'schema','nonce','path','registration','launchInstanceGuid','state','instanceGuids','lastTaskResult'},'Task readback fields')
        _need(exit['expectedSHA256']==t['expected']['sha256'] and obj(task['registration'])==expected['registration'],'Exact task registration')
        _need(task['nonce']==nonce and task['path']=='\\BimeronStep8Probe' and task['state']==3 and task['instanceGuids']==[] and task['launchInstanceGuid']==launch['guid']==pin['launch']['guid'],'Task not exactly idle')
        journal=raw(d['terminalJournal']);log=snapshot(journal,nonce,pin['producer']);_need(not log['partialBytes'],'Partial terminal');rows=log['records'];end=rows[-1]
        _need(journal.endswith(b'\n') and end['kind']=='end' and end['nonce']==nonce and end['producer']==pin['producer'],'Bound terminal required')
        if end['status']=='cancelled':
            stop=obj(d['stopRequest']);_need(end['requestId']==stop['requestId']==final['requestId'] and stop['nonce']==nonce,'Exact cooperative stop')
        else:
            _need(end['status']=='complete' and final['completed'] is True and task['lastTaskResult']==0,'Natural completion')
            log=snapshot(journal,nonce,pin['producer']);timer=_json(log['records'][0]['status'])
            _need((end['ticks']-timer['origin'])/timer['frequency']>=900,'Short natural producer')
        return result('PASS',[],refs=dict(readerClosure=d['readerClosures']['sha256'],taskClosure=d['taskClosure']['sha256']))
    except (ValueError,KeyError,TypeError,StopIteration,IndexError,ZeroDivisionError) as e:return result('INCONCLUSIVE',[str(e)])

def check_independent_absence(final,binding,nonce):
    try:
        proof=_json(final['proof'])
        if proof.get('schema')=='full300-no-supervisor-attempt-v1':
            _need(binding is None and set(proof)=={'schema','nonce'} and proof['nonce']==nonce and check_exact_drain(final['prelaunch_drain'],nonce)['status']=='PASS','No-supervisor restoration proof')
            _need('Bimeron Step8' not in final['ras'],'Owned RAS profile remains')
            return result('PASS',[],rasAbsent=True,ownerAbsent=True,taskReady=True,refs=dict(noAttempt=_hash(final['proof'])))
        ready=_json(final['exit_ready']);task=_json(final['task_final']);baseline=_json(final['task_registration'])
        _need(final['nonce']==nonce==proof['nonce']==ready['nonce'],'Exit nonce')
        _need(ready['proofSHA256']==_hash(final['proof']) and ready['supervisorOnceSHA256']==proof['supervisorOnceSHA256']==_hash(final['once']),'Original supervisor exit binding')
        _need(task['xml']==baseline['xml'] and task['sddl']==baseline['sddl'] and task['state']==3 and task['instanceGuids']==[] and task['instanceGuid']==_json(final['task_instance'])['instanceGuid'],'Exact supervisor task exit')
        _need(isinstance(baseline.get('fileSddl'),str) and bool(baseline['fileSddl']) and task.get('fileSddl')==baseline['fileSddl'],'Exact supervisor task file ACL')
        if binding is None:
            _need(proof['schema']=='full300-no-launch-v1' and proof['sealed'] is True and proof['launchAttempted'] is False,'Active no-launch seal')
        else:
            _need(proof['schema']=='full300-owner-exit-v1' and proof['waitResult']=='signalled' and proof['owner']==final['owner_identity'],'Retained native exit')
            ref=proof['nativeStatus'];raw=final['files'][ref['name']];_need(_hash(raw)==ref['sha256'],'Final native status hash');status=_json(raw)
            _need(all(status[k]==v for k,v in binding.items()) and status['State']=='CLOSED','Native close not acknowledged')
            inventory=_json(final['guids']);_need(isinstance(inventory,list) and len(inventory)==22 and len(set(inventory))==22,'Complete GUID inventory')
            tree=ET.fromstring(final['bfe']);_need(tree.tag=='wfpstate' and all(tree.find(n) is not None for n in ('providers','subLayers','layers')),'Incomplete fresh BFE inventory');texts={str(x.text or '').strip().lower().strip('{}') for x in tree.iter()}
            _need(all(str(g).lower().strip('{}') not in texts for g in inventory),'Owned GUID still present')
        _need('Bimeron Step8' not in final['ras'],'Owned RAS profile remains')
        return result('PASS',[],rasAbsent=True,ownerAbsent=True,taskReady=True,refs=dict(exit=_hash(final['proof']),bfe=_hash(final['bfe']),task=_hash(final['task_final'])))
    except (ValueError,KeyError,TypeError,ET.ParseError) as e:return result('INCONCLUSIVE',[str(e)])
