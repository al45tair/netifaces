#include <Python.h>

#ifndef WIN32

#  include <sys/types.h>
#  include <sys/socket.h>
#  include <net/if.h>
#  include <netdb.h>

#  if HAVE_SOCKET_IOCTLS
#    include <sys/ioctl.h>
#    include <netinet/in.h>
#    include <arpa/inet.h>
#if defined(__sun)
#include <unistd.h>
#include <stropts.h>
#include <sys/sockio.h>
#endif
#  endif /* HAVE_SOCKET_IOCTLS */

/* For logical interfaces support we convert all names to same name prefixed with l */
#if HAVE_SIOCGLIFNUM
#define CNAME(x) l##x
#else
#define CNAME(x) x
#endif

#if HAVE_NET_IF_DL_H
#  include <net/if_dl.h>
#endif

/* For the benefit of stupid platforms (Linux), include all the sockaddr
   definitions we can lay our hands on. It can also be useful for the benefit
   of another stupid platform (FreeBSD, see PR 152036). */
#include <netinet/in.h>
#  if HAVE_NETASH_ASH_H
#    include <netash/ash.h>
#  endif
#  if HAVE_NETATALK_AT_H
#    include <netatalk/at.h>
#  endif
#  if HAVE_NETAX25_AX25_H
#    include <netax25/ax25.h>
#  endif
#  if HAVE_NETECONET_EC_H
#    include <neteconet/ec.h>
#  endif
#  if HAVE_NETIPX_IPX_H
#    include <netipx/ipx.h>
#  endif
#  if HAVE_NETPACKET_PACKET_H
#    include <netpacket/packet.h>
#  endif
#  if HAVE_NETROSE_ROSE_H
#    include <netrose/rose.h>
#  endif
#  if HAVE_LINUX_IRDA_H
#    include <linux/irda.h>
#  endif
#  if HAVE_LINUX_ATM_H
#    include <linux/atm.h>
#  endif
#  if HAVE_LINUX_LLC_H
#    include <linux/llc.h>
#  endif
#  if HAVE_LINUX_TIPC_H
#    include <linux/tipc.h>
#  endif
#  if HAVE_LINUX_DN_H
#    include <linux/dn.h>
#  endif

/* Map address families to sizes of sockaddr structs */
static int af_to_len(int af) 
{
  switch (af) {
  case AF_INET: return sizeof (struct sockaddr_in);
#if defined(AF_INET6) && HAVE_SOCKADDR_IN6
  case AF_INET6: return sizeof (struct sockaddr_in6);
#endif
#if defined(AF_AX25) && HAVE_SOCKADDR_AX25
#  if defined(AF_NETROM)
  case AF_NETROM: /* I'm assuming this is carried over x25 */
#  endif
  case AF_AX25: return sizeof (struct sockaddr_ax25);
#endif
#if defined(AF_IPX) && HAVE_SOCKADDR_IPX
  case AF_IPX: return sizeof (struct sockaddr_ipx);
#endif
#if defined(AF_APPLETALK) && HAVE_SOCKADDR_AT
  case AF_APPLETALK: return sizeof (struct sockaddr_at);
#endif
#if defined(AF_ATMPVC) && HAVE_SOCKADDR_ATMPVC
  case AF_ATMPVC: return sizeof (struct sockaddr_atmpvc);
#endif
#if defined(AF_ATMSVC) && HAVE_SOCKADDR_ATMSVC
  case AF_ATMSVC: return sizeof (struct sockaddr_atmsvc);
#endif
#if defined(AF_X25) && HAVE_SOCKADDR_X25
  case AF_X25: return sizeof (struct sockaddr_x25);
#endif
#if defined(AF_ROSE) && HAVE_SOCKADDR_ROSE
  case AF_ROSE: return sizeof (struct sockaddr_rose);
#endif
#if defined(AF_DECnet) && HAVE_SOCKADDR_DN
  case AF_DECnet: return sizeof (struct sockaddr_dn);
#endif
#if defined(AF_PACKET) && HAVE_SOCKADDR_LL
  case AF_PACKET: return sizeof (struct sockaddr_ll);
#endif
#if defined(AF_ASH) && HAVE_SOCKADDR_ASH
  case AF_ASH: return sizeof (struct sockaddr_ash);
#endif
#if defined(AF_ECONET) && HAVE_SOCKADDR_EC
  case AF_ECONET: return sizeof (struct sockaddr_ec);
#endif
#if defined(AF_IRDA) && HAVE_SOCKADDR_IRDA
  case AF_IRDA: return sizeof (struct sockaddr_irda);
#endif
  }
  return sizeof (struct sockaddr);
}

#if !HAVE_SOCKADDR_SA_LEN
#define SA_LEN(sa)      af_to_len(sa->sa_family)
#if HAVE_SIOCGLIFNUM
#define SS_LEN(sa)      af_to_len(sa->ss_family)
#else
#define SS_LEN(sa)      SA_LEN(sa)
#endif
#else
#define SA_LEN(sa)      sa->sa_len
#endif /* !HAVE_SOCKADDR_SA_LEN */

#  if HAVE_GETIFADDRS
#    include <ifaddrs.h>
#  endif /* HAVE_GETIFADDRS */

#  if !HAVE_GETIFADDRS && (!HAVE_SOCKET_IOCTLS || !HAVE_SIOCGIFCONF)
/* If the platform doesn't define, what we need, barf.  If you're seeing this,
   it means you need to write suitable code to retrieve interface information
   on your system. */
#    error You need to add code for your platform.
#  endif

#else /* defined(WIN32) */

#define _WIN32_WINNT 0x0501

#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <iphlpapi.h>

#endif /* defined(WIN32) */

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

/* On systems without AF_LINK (Windows, for instance), define it anyway, but
   give it a crazy value.  On Linux, which has AF_PACKET but not AF_LINK,
   define AF_LINK as the latter instead. */
#ifndef AF_LINK
#  ifdef AF_PACKET
#    define AF_LINK  AF_PACKET
#  else
#    define AF_LINK  -1000
#  endif
#  define HAVE_AF_LINK 0
#else
#  define HAVE_AF_LINK 1
#endif

#if !defined(WIN32)
#if  !HAVE_GETNAMEINFO
#undef getnameinfo
#undef NI_NUMERICHOST

#define getnameinfo our_getnameinfo
#define NI_NUMERICHOST 1

/* A very simple getnameinfo() for platforms without */
static int
getnameinfo (const struct sockaddr *addr, int addr_len,
             char *buffer, int buflen,
             char *buf2, int buf2len,
             int flags)
{
  switch (addr->sa_family) {
  case AF_INET:
    {
      const struct sockaddr_in *sin = (struct sockaddr_in *)addr;
      const unsigned char *bytes = (unsigned char *)&sin->sin_addr.s_addr;
      char tmpbuf[20];

      sprintf (tmpbuf, "%d.%d.%d.%d",
               bytes[0], bytes[1], bytes[2], bytes[3]);

      strncpy (buffer, tmpbuf, buflen);
    }
    break;
#ifdef AF_INET6
  case AF_INET6:
    {
      const struct sockaddr_in6 *sin = (const struct sockaddr_in6 *)addr;
      const unsigned char *bytes = sin->sin6_addr.s6_addr;
      int n;
      char tmpbuf[80], *ptr = tmpbuf;
      int done_double_colon = FALSE;
      int colon_mode = FALSE;

      for (n = 0; n < 8; ++n) {
        unsigned char b1 = bytes[2 * n];
        unsigned char b2 = bytes[2 * n + 1];

        if (b1) {
          if (colon_mode) {
            colon_mode = FALSE;
            *ptr++ = ':';
          }
          sprintf (ptr, "%x%02x", b1, b2);
          ptr += strlen (ptr);
          *ptr++ = ':';
        } else if (b2) {
          if (colon_mode) {
            colon_mode = FALSE;
            *ptr++ = ':';
          }
          sprintf (ptr, "%x", b2);
          ptr += strlen (ptr);
          *ptr++ = ':';
        } else {
          if (!colon_mode) {
            if (done_double_colon) {
              *ptr++ = '0';
              *ptr++ = ':';
            } else {
              if (n == 0)
                *ptr++ = ':';
              colon_mode = TRUE;
              done_double_colon = TRUE;
            }
          }
        }
      }
      if (colon_mode) {
        colon_mode = FALSE;
        *ptr++ = ':';
        *ptr++ = '\0';
      } else {
        *--ptr = '\0';
      }

      strncpy (buffer, tmpbuf, buflen);
    }
    break;
#endif /* AF_INET6 */
  default:
    return -1;
  }

  return 0;
}
#endif

static int
string_from_sockaddr (struct sockaddr *addr,
                      char *buffer,
                      int buflen)
{
  struct sockaddr* bigaddr = 0;
  int failure;
  struct sockaddr* gniaddr;
  socklen_t gnilen;

  if (!addr || addr->sa_family == AF_UNSPEC)
    return -1;

  if (SA_LEN(addr) < af_to_len(addr->sa_family)) {
    /* Someteims ifa_netmask can be truncated. So let's detruncate it.  FreeBSD
     * PR: kern/152036: getifaddrs(3) returns truncated sockaddrs for netmasks
     * -- http://www.freebsd.org/cgi/query-pr.cgi?pr=152036 */
    gnilen = af_to_len(addr->sa_family);
    bigaddr = calloc(1, gnilen);
    if (!bigaddr)
      return -1;
    memcpy(bigaddr, addr, SA_LEN(addr));
#if HAVE_SOCKADDR_SA_LEN
    bigaddr->sa_len = gnilen;
#endif
    gniaddr = bigaddr;
  } else {
    gnilen = SA_LEN(addr);
    gniaddr = addr;
  }

  failure = getnameinfo (gniaddr, gnilen,
                         buffer, buflen,
                         NULL, 0,
                         NI_NUMERICHOST);

  if (bigaddr) {
    free(bigaddr);
    bigaddr = 0;
  }

  if (failure) {
    size_t n, len;
    char *ptr;
    const char *data;
      
    len = SA_LEN(addr);

#if HAVE_AF_LINK
    /* BSD-like systems have AF_LINK */
    if (addr->sa_family == AF_LINK) {
      struct sockaddr_dl *dladdr = (struct sockaddr_dl *)addr;
      len = dladdr->sdl_alen;
      data = LLADDR(dladdr);
    } else {
#endif
#if defined(AF_PACKET)
      /* Linux has AF_PACKET instead */
      if (addr->sa_family == AF_PACKET) {
        struct sockaddr_ll *lladdr = (struct sockaddr_ll *)addr;
        len = lladdr->sll_halen;
        data = (const char *)lladdr->sll_addr;
      } else {
#endif
        /* We don't know anything about this sockaddr, so just display
           the entire data area in binary. */
        len -= (sizeof (struct sockaddr) - sizeof (addr->sa_data));
        data = addr->sa_data;
#if defined(AF_PACKET)
      }
#endif
#if HAVE_AF_LINK
    }
#endif

    if (buflen < 3 * len)
      return -1;

    ptr = buffer;
    buffer[0] = '\0';

    for (n = 0; n < len; ++n) {
      sprintf (ptr, "%02x:", data[n] & 0xff);
      ptr += 3;
    }
    *--ptr = '\0';
  }

  if (!buffer[0])
    return -1;

  return 0;
}
#endif /* !defined(WIN32) */

#if defined(WIN32)
static int
compare_bits (const void *pva,
              const void *pvb,
              unsigned bits)
{
  const unsigned char *pa = (const unsigned char *)pva;
  const unsigned char *pb = (const unsigned char *)pvb;
  unsigned char a, b;
  static unsigned char masks[] = {
    0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe
  };
  while (bits >= 8) {
    a = *pa++;
    b = *pb++;
    if (a < b)
      return -1;
    else if (a > b)
      return +1;
    bits -= 8;
  }

  if (bits) {
    a = *pa++ & masks[bits];
    b = *pb++ & masks[bits];
    if (a < b)
      return -1;
    else if (a > b)
      return +1;
  }

  return 0;
}
#endif

static int
add_to_family (PyObject *result, int family, PyObject *dict)
{
  if (!PyDict_Size (dict))
    return TRUE;

  PyObject *py_family = PyInt_FromLong (family);
  PyObject *list = PyDict_GetItem (result, py_family);

  if (!py_family) {
    Py_DECREF (dict);
    Py_XDECREF (list);
    return FALSE;
  }

  if (!list) {
    list = PyList_New (1);
    if (!list) {
      Py_DECREF (dict);
      Py_DECREF (py_family);
      return FALSE;
    }

    PyList_SET_ITEM (list, 0, dict);
    PyDict_SetItem (result, py_family, list);
    Py_DECREF (list);
  } else {
    PyList_Append (list, dict);
    Py_DECREF (dict);
  }

  return TRUE;
}

static PyObject *
ifaddrs (PyObject *self, PyObject *args)
{
  const char *ifname;
  PyObject *result;
  int found = FALSE;
#if defined(WIN32)
  PIP_ADAPTER_ADDRESSES pAdapterAddresses = NULL, pInfo = NULL;
  ULONG ulBufferLength = 0;
  DWORD dwRet;
  PIP_ADAPTER_UNICAST_ADDRESS pUniAddr;
#endif

  if (!PyArg_ParseTuple (args, "s", &ifname))
    return NULL;

  result = PyDict_New ();

  if (!result)
    return NULL;

#if defined(WIN32)
  /* First, retrieve the adapter information.  We do this in a loop, in
     case someone adds or removes adapters in the meantime. */
  do {
    dwRet = GetAdaptersAddresses (AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL,
                                  pAdapterAddresses, &ulBufferLength);

    if (dwRet == ERROR_BUFFER_OVERFLOW) {
      if (pAdapterAddresses)
        free (pAdapterAddresses);
      pAdapterAddresses = (PIP_ADAPTER_ADDRESSES)malloc (ulBufferLength);

      if (!pAdapterAddresses) {
        Py_DECREF (result);
        PyErr_SetString (PyExc_MemoryError, "Not enough memory");
        return NULL;
      }
    }
  } while (dwRet == ERROR_BUFFER_OVERFLOW);

  /* If we failed, then fail in Python too */
  if (dwRet != ERROR_SUCCESS && dwRet != ERROR_NO_DATA) {
    Py_DECREF (result);
    if (pAdapterAddresses)
      free (pAdapterAddresses);

    PyErr_SetString (PyExc_OSError,
                     "Unable to obtain adapter information.");
    return NULL;
  }

  for (pInfo = pAdapterAddresses; pInfo; pInfo = pInfo->Next) {
    char buffer[256];

    if (strcmp (pInfo->AdapterName, ifname) != 0)
      continue;

    found = TRUE;

    /* Do the physical address */
    if (256 >= 3 * pInfo->PhysicalAddressLength) {
      PyObject *hwaddr, *dict;
      char *ptr = buffer;
      unsigned n;
      
      *ptr = '\0';
      for (n = 0; n < pInfo->PhysicalAddressLength; ++n) {
        sprintf (ptr, "%02x:", pInfo->PhysicalAddress[n] & 0xff);
        ptr += 3;
      }
      *--ptr = '\0';

      hwaddr = PyString_FromString (buffer);
      dict = PyDict_New ();

      if (!dict) {
        Py_XDECREF (hwaddr);
        Py_DECREF (result);
        free (pAdapterAddresses);
        return NULL;
      }

      PyDict_SetItemString (dict, "addr", hwaddr);
      Py_DECREF (hwaddr);

      if (!add_to_family (result, AF_LINK, dict)) {
        Py_DECREF (result);
        free (pAdapterAddresses);
        return NULL;
      }
    }

    for (pUniAddr = pInfo->FirstUnicastAddress;
         pUniAddr;
         pUniAddr = pUniAddr->Next) {
      DWORD dwLen = sizeof (buffer);
      INT iRet = WSAAddressToString (pUniAddr->Address.lpSockaddr,
                                     pUniAddr->Address.iSockaddrLength,
                                     NULL,
                                     (LPTSTR)buffer,
                                     &dwLen);
      PyObject *addr;
      PyObject *mask = NULL;
      PyObject *bcast = NULL;
      PIP_ADAPTER_PREFIX pPrefix;
      short family = pUniAddr->Address.lpSockaddr->sa_family;

      if (iRet)
        continue;

      addr = PyString_FromString (buffer);

      /* Find the netmask, where possible */
      if (family == AF_INET) {
         struct sockaddr_in *pAddr
          = (struct sockaddr_in *)pUniAddr->Address.lpSockaddr;

        for (pPrefix = pInfo->FirstPrefix;
             pPrefix;
             pPrefix = pPrefix->Next) {
          struct sockaddr_in *pPrefixAddr
            = (struct sockaddr_in *)pPrefix->Address.lpSockaddr;
          struct sockaddr_in maskAddr, bcastAddr;
          unsigned toDo;
          unsigned wholeBytes, remainingBits;
          unsigned char *pMaskBits, *pBcastBits;

          if (pPrefixAddr->sin_family != AF_INET)
            continue;
          
          if (compare_bits (&pPrefixAddr->sin_addr,
                            &pAddr->sin_addr,
                            pPrefix->PrefixLength) != 0)
            continue;

          memcpy (&maskAddr,
                  pPrefix->Address.lpSockaddr,
                  sizeof (maskAddr));
          memcpy (&bcastAddr,
                  pPrefix->Address.lpSockaddr,
                  sizeof (bcastAddr));
                  
          wholeBytes = pPrefix->PrefixLength >> 3;
          remainingBits = pPrefix->PrefixLength & 7;

          if (wholeBytes >= 4)
            continue;

          toDo = wholeBytes;
          pMaskBits = (unsigned char *)&maskAddr.sin_addr;

          while (toDo--)
            *pMaskBits++ = 0xff;

          toDo = 4 - wholeBytes;

          pBcastBits = (unsigned char *)&bcastAddr.sin_addr + wholeBytes;

          if (remainingBits) {
            static const unsigned char masks[] = {
              0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe
            };
            *pMaskBits++ = masks[remainingBits];
            *pBcastBits &= masks[remainingBits];
            *pBcastBits++ |= ~masks[remainingBits];
            --toDo;
          }

          while (toDo--) {
            *pMaskBits++ = 0;
            *pBcastBits++ = 0xff;
          }

          dwLen = sizeof (buffer);
          iRet = WSAAddressToString ((SOCKADDR *)&maskAddr,
                                     sizeof (maskAddr),
                                     NULL,
                                     (LPTSTR)buffer,
                                     &dwLen);

          if (iRet == 0)
            mask = PyString_FromString (buffer);
          
          dwLen = sizeof (buffer);
          iRet = WSAAddressToString ((SOCKADDR *)&bcastAddr,
                                     sizeof (bcastAddr),
                                     NULL,
                                     (LPTSTR)buffer,
                                     &dwLen);

          if (iRet == 0)
            bcast = PyString_FromString (buffer);
          else
            printf ("%d\n", iRet);

          break;
        }
      } else if (family == AF_INET6) {
        struct sockaddr_in6 *pAddr
          = (struct sockaddr_in6 *)pUniAddr->Address.lpSockaddr;

        for (pPrefix = pInfo->FirstPrefix;
             pPrefix;
             pPrefix = pPrefix->Next) {
          struct sockaddr_in6 *pPrefixAddr
            = (struct sockaddr_in6 *)pPrefix->Address.lpSockaddr;
          struct sockaddr_in6 maskAddr, bcastAddr;
          unsigned toDo;
          unsigned wholeBytes, remainingBits;
          unsigned char *pMaskBits, *pBcastBits;

          if (pPrefixAddr->sin6_family != AF_INET6)
            continue;
          
          if (compare_bits (&pPrefixAddr->sin6_addr,
                            &pAddr->sin6_addr,
                            pPrefix->PrefixLength) != 0)
            continue;

          memcpy (&maskAddr,
                  pPrefix->Address.lpSockaddr,
                  sizeof (maskAddr));
          memcpy (&bcastAddr,
                  pPrefix->Address.lpSockaddr,
                  sizeof (bcastAddr));
                  
          wholeBytes = pPrefix->PrefixLength >> 3;
          remainingBits = pPrefix->PrefixLength & 7;

          if (wholeBytes >= 8)
            continue;

          toDo = wholeBytes;
          pMaskBits = (unsigned char *)&maskAddr.sin6_addr;

          while (toDo--)
            *pMaskBits++ = 0xff;

          toDo = 8 - wholeBytes;

          pBcastBits = (unsigned char *)&bcastAddr.sin6_addr + wholeBytes;

          if (remainingBits) {
            static const unsigned char masks[] = {
              0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe
            };
            *pMaskBits++ = masks[remainingBits];
            *pBcastBits &= masks[remainingBits];
            *pBcastBits++ |= ~masks[remainingBits];
            --toDo;
          }

          while (toDo--) {
            *pMaskBits++ = 0;
            *pBcastBits++ = 0xff;
          }

          dwLen = sizeof (buffer);
          iRet = WSAAddressToString ((SOCKADDR *)&maskAddr,
                                     sizeof (maskAddr),
                                     NULL,
                                     (LPTSTR)buffer,
                                     &dwLen);

          if (iRet == 0)
            mask = PyString_FromString (buffer);
          
          dwLen = sizeof (buffer);
          iRet = WSAAddressToString ((SOCKADDR *)&bcastAddr,
                                     sizeof (bcastAddr),
                                     NULL,
                                     (LPTSTR)buffer,
                                     &dwLen);

          if (iRet == 0)
            bcast = PyString_FromString (buffer);

          break;
        }
      }

      PyObject *dict;

      dict = PyDict_New ();

      if (!dict) {
        Py_XDECREF (addr);
        Py_XDECREF (mask);
        Py_XDECREF (bcast);
        Py_DECREF (result);
        free (pAdapterAddresses);
        return NULL;
      }

      if (addr)
        PyDict_SetItemString (dict, "addr", addr);
      if (mask)
        PyDict_SetItemString (dict, "netmask", mask);
      if (bcast)
        PyDict_SetItemString (dict, "broadcast", bcast);

      Py_XDECREF (addr);
      Py_XDECREF (mask);
      Py_XDECREF (bcast);

      if (!add_to_family (result, family, dict)) {
        Py_DECREF (result);
        free ((void *)pAdapterAddresses);
        return NULL;
      }
    }
  }

  free ((void *)pAdapterAddresses);
#elif HAVE_GETIFADDRS
  struct ifaddrs *addrs = NULL;
  struct ifaddrs *addr = NULL;

  if (getifaddrs (&addrs) < 0) {
    Py_DECREF (result);
    PyErr_SetFromErrno (PyExc_OSError);
    return NULL;
  }

  for (addr = addrs; addr; addr = addr->ifa_next) {
    char buffer[256];
    PyObject *pyaddr = NULL, *netmask = NULL, *braddr = NULL;

    if (strcmp (addr->ifa_name, ifname) != 0)
      continue;
 
    /* We mark the interface as found, even if there are no addresses;
       this results in sensible behaviour for these few cases. */
    found = TRUE;

    /* Sometimes there are records without addresses (e.g. in the case of a
       dial-up connection via ppp, which on Linux can have a link address
       record with no actual address).  We skip these as they aren't useful.
       Thanks to Christian Kauhaus for reporting this issue. */
    if (!addr->ifa_addr)
      continue;  

    if (string_from_sockaddr (addr->ifa_addr, buffer, sizeof (buffer)) == 0)
      pyaddr = PyString_FromString (buffer);

    if (string_from_sockaddr (addr->ifa_netmask, buffer, sizeof (buffer)) == 0)
      netmask = PyString_FromString (buffer);

    if (string_from_sockaddr (addr->ifa_broadaddr, buffer, sizeof (buffer)) == 0)
      braddr = PyString_FromString (buffer);

    PyObject *dict = PyDict_New();

    if (!dict) {
      Py_XDECREF (pyaddr);
      Py_XDECREF (netmask);
      Py_XDECREF (braddr);
      Py_DECREF (result);
      freeifaddrs (addrs);
      return NULL;
    }

    if (pyaddr)
      PyDict_SetItemString (dict, "addr", pyaddr);
    if (netmask)
      PyDict_SetItemString (dict, "netmask", netmask);

    if (braddr) {
      if (addr->ifa_flags & (IFF_POINTOPOINT | IFF_LOOPBACK))
        PyDict_SetItemString (dict, "peer", braddr);
      else
        PyDict_SetItemString (dict, "broadcast", braddr);
    }

    Py_XDECREF (pyaddr);
    Py_XDECREF (netmask);
    Py_XDECREF (braddr);

    if (!add_to_family (result, addr->ifa_addr->sa_family, dict)) {
      Py_DECREF (result);
      freeifaddrs (addrs);
      return NULL;
    }
  }

  freeifaddrs (addrs);
#elif HAVE_SOCKET_IOCTLS
  
  int sock = socket(AF_INET, SOCK_DGRAM, 0);

  if (sock < 0) {
    Py_DECREF (result);
    PyErr_SetFromErrno (PyExc_OSError);
    return NULL;
  }

  struct CNAME(ifreq) ifr;
  PyObject *addr = NULL, *netmask = NULL, *braddr = NULL, *dstaddr = NULL;
  int is_p2p = FALSE;
  char buffer[256];

  strncpy (ifr.CNAME(ifr_name), ifname, IFNAMSIZ);

#if HAVE_SIOCGIFHWADDR
  if (ioctl (sock, SIOCGIFHWADDR, &ifr) == 0) {
    found = TRUE;

    if (string_from_sockaddr ((struct sockaddr *)&ifr.CNAME(ifr_addr), buffer, sizeof (buffer)) == 0) {
      PyObject *hwaddr = PyString_FromString (buffer);
      PyObject *dict = PyDict_New ();

      if (!hwaddr || !dict) {
        Py_XDECREF (hwaddr);
        Py_XDECREF (dict);
        Py_XDECREF (result);
        close (sock);
        return NULL;
      }

      PyDict_SetItemString (dict, "addr", hwaddr);
      Py_DECREF (hwaddr);

      if (!add_to_family (result, AF_LINK, dict)) {
        Py_DECREF (result);
        close (sock);
        return NULL;
      }
    }
  }
#endif

#if HAVE_SIOCGIFADDR
#if HAVE_SIOCGLIFNUM
  if (ioctl (sock, SIOCGLIFADDR, &ifr) == 0) {
#else
  if (ioctl (sock, SIOCGIFADDR, &ifr) == 0) {
#endif
    found = TRUE;

    if (string_from_sockaddr ((struct sockaddr *)&ifr.CNAME(ifr_addr), buffer, sizeof (buffer)) == 0)
      addr = PyString_FromString (buffer);
  }
#endif

#if HAVE_SIOCGIFNETMASK
#if HAVE_SIOCGLIFNUM
  if (ioctl (sock, SIOCGLIFNETMASK, &ifr) == 0) {
#else
  if (ioctl (sock, SIOCGIFNETMASK, &ifr) == 0) {
#endif
    found = TRUE;

    if (string_from_sockaddr ((struct sockaddr *)&ifr.CNAME(ifr_addr), buffer, sizeof (buffer)) == 0)
      netmask = PyString_FromString (buffer);
  }
#endif

#if HAVE_SIOCGIFFLAGS
#if HAVE_SIOCGLIFNUM
  if (ioctl (sock, SIOCGLIFFLAGS, &ifr) == 0) {
#else
  if (ioctl (sock, SIOCGIFFLAGS, &ifr) == 0) {
#endif
    found = TRUE;

    if (ifr.CNAME(ifr_flags) & IFF_POINTOPOINT)
      is_p2p = TRUE;
  }
#endif

#if HAVE_SIOCGIFBRDADDR
#if HAVE_SIOCGLIFNUM
  if (!is_p2p && ioctl (sock, SIOCGLIFBRDADDR, &ifr) == 0) {
#else
  if (!is_p2p && ioctl (sock, SIOCGIFBRDADDR, &ifr) == 0) {
#endif
    found = TRUE;

    if (string_from_sockaddr ((struct sockaddr *)&ifr.CNAME(ifr_addr), buffer, sizeof (buffer)) == 0)
      braddr = PyString_FromString (buffer);
  }
#endif

#if HAVE_SIOCGIFDSTADDR
#if HAVE_SIOCGLIFNUM
  if (is_p2p && ioctl (sock, SIOCGLIFBRDADDR, &ifr) == 0) {
#else
  if (is_p2p && ioctl (sock, SIOCGIFBRDADDR, &ifr) == 0) {
#endif
    found = TRUE;

    if (string_from_sockaddr ((struct sockaddr *)&ifr.CNAME(ifr_addr), buffer, sizeof (buffer)) == 0)
      dstaddr = PyString_FromString (buffer);
  }
#endif

  PyObject *dict = PyDict_New();

  if (!dict) {
    Py_XDECREF (addr);
    Py_XDECREF (netmask);
    Py_XDECREF (braddr);
    Py_XDECREF (dstaddr);
    Py_DECREF (result);
    close (sock);
    return NULL;
  }

  if (addr)
    PyDict_SetItemString (dict, "addr", addr);
  if (netmask)
    PyDict_SetItemString (dict, "netmask", netmask);
  if (braddr)
    PyDict_SetItemString (dict, "broadcast", braddr);
  if (dstaddr)
    PyDict_SetItemString (dict, "peer", dstaddr);

  Py_XDECREF (addr);
  Py_XDECREF (netmask);
  Py_XDECREF (braddr);
  Py_XDECREF (dstaddr);

  if (!add_to_family (result, AF_INET, dict)) {
    Py_DECREF (result);
    close (sock);
    return NULL;
  }

  close (sock);
#endif /* HAVE_SOCKET_IOCTLS */

  if (found)
    return result;
  else {
    Py_DECREF (result);
    PyErr_SetString (PyExc_ValueError, 
                     "You must specify a valid interface name.");
    return NULL;
  }
}

static PyObject *
interfaces (PyObject *self)
{
  PyObject *result;

#if defined(WIN32)
  PIP_ADAPTER_ADDRESSES pAdapterAddresses = NULL, pInfo = NULL;
  ULONG ulBufferLength = 0;
  DWORD dwRet;

  /* First, retrieve the adapter information */
  do {
    dwRet = GetAdaptersAddresses(AF_UNSPEC, 0, NULL,
                                 pAdapterAddresses, &ulBufferLength);

    if (dwRet == ERROR_BUFFER_OVERFLOW) {
      if (pAdapterAddresses)
        free (pAdapterAddresses);
      pAdapterAddresses = (PIP_ADAPTER_ADDRESSES)malloc (ulBufferLength);

      if (!pAdapterAddresses) {
        PyErr_SetString (PyExc_MemoryError, "Not enough memory");
        return NULL;
      }
    }
  } while (dwRet == ERROR_BUFFER_OVERFLOW);

  /* If we failed, then fail in Python too */
  if (dwRet != ERROR_SUCCESS && dwRet != ERROR_NO_DATA) {
    if (pAdapterAddresses)
      free (pAdapterAddresses);

    PyErr_SetString (PyExc_OSError,
                     "Unable to obtain adapter information.");
    return NULL;
  }

  result = PyList_New(0);

  if (dwRet == ERROR_NO_DATA) {
    free (pAdapterAddresses);
    return result;
  }

  for (pInfo = pAdapterAddresses; pInfo; pInfo = pInfo->Next) {
    PyObject *ifname = (PyObject *)PyString_FromString (pInfo->AdapterName);

    PyList_Append (result, ifname);
    Py_DECREF (ifname);
  }

  free (pAdapterAddresses);
#elif HAVE_GETIFADDRS
  const char *prev_name = NULL;
  struct ifaddrs *addrs = NULL;
  struct ifaddrs *addr = NULL;

  result = PyList_New (0);

  if (getifaddrs (&addrs) < 0) {
    Py_DECREF (result);
    PyErr_SetFromErrno (PyExc_OSError);
    return NULL;
  }

  for (addr = addrs; addr; addr = addr->ifa_next) {
    if (!prev_name || strncmp (addr->ifa_name, prev_name, IFNAMSIZ) != 0) {
      PyObject *ifname = PyString_FromString (addr->ifa_name);
    
      if (!PySequence_Contains (result, ifname))
        PyList_Append (result, ifname);
      Py_DECREF (ifname);
      prev_name = addr->ifa_name;
    }
  }

  freeifaddrs (addrs);
#elif HAVE_SIOCGIFCONF
  const char *prev_name = NULL;
  int fd = socket (AF_INET, SOCK_DGRAM, 0);
  struct CNAME(ifconf) ifc;
  int len = -1;

  if (fd < 0) {
    PyErr_SetFromErrno (PyExc_OSError);
    return NULL;
  }

  // Try to find out how much space we need
#if HAVE_SIOCGSIZIFCONF
  if (ioctl (fd, SIOCGSIZIFCONF, &len) < 0)
    len = -1;
#elif HAVE_SIOCGLIFNUM
  { struct lifnum lifn;
    lifn.lifn_family = AF_UNSPEC;
    lifn.lifn_flags = LIFC_NOXMIT | LIFC_TEMPORARY | LIFC_ALLZONES;
    ifc.lifc_family = AF_UNSPEC;
    ifc.lifc_flags = LIFC_NOXMIT | LIFC_TEMPORARY | LIFC_ALLZONES;
    if (ioctl (fd, SIOCGLIFNUM, (char *)&lifn) < 0)
      len = -1;
    else
      len = lifn.lifn_count;
  }
#endif

  // As a last resort, guess
  if (len < 0)
    len = 64;

  ifc.CNAME(ifc_len) = (int)(len * sizeof (struct CNAME(ifreq)));
  ifc.CNAME(ifc_buf) = malloc (ifc.CNAME(ifc_len));

  if (!ifc.CNAME(ifc_buf)) {
    PyErr_SetString (PyExc_MemoryError, "Not enough memory");
    close (fd);
    return NULL;
  }

#if HAVE_SIOCGLIFNUM
  if (ioctl (fd, SIOCGLIFCONF, &ifc) < 0) {
#else
  if (ioctl (fd, SIOCGIFCONF, &ifc) < 0) {
#endif
    free (ifc.CNAME(ifc_req));
    PyErr_SetFromErrno (PyExc_OSError);
    close (fd);
    return NULL;
  }

  result = PyList_New (0);
  struct CNAME(ifreq) *pfreq = ifc.CNAME(ifc_req);
  struct CNAME(ifreq) *pfreqend = (struct CNAME(ifreq) *)((char *)pfreq
                                                          + ifc.CNAME(ifc_len));
  while (pfreq < pfreqend) {
    if (!prev_name || strncmp (prev_name, pfreq->CNAME(ifr_name), IFNAMSIZ) != 0) {
      PyObject *name = PyString_FromString (pfreq->CNAME(ifr_name));

      if (!PySequence_Contains (result, name))
        PyList_Append (result, name);
      Py_XDECREF (name);

      prev_name = pfreq->CNAME(ifr_name);
    }

#if !HAVE_SOCKADDR_SA_LEN
    ++pfreq;
#else
    /* On some platforms, the ifreq struct can *grow*(!) if the socket address
       is very long.  Mac OS X is such a platform. */
    {
      size_t len = sizeof (struct CNAME(ifreq));
      if (pfreq->ifr_addr.sa_len > sizeof (struct sockaddr))
        len = len - sizeof (struct sockaddr) + pfreq->ifr_addr.sa_len;
        pfreq = (struct CNAME(ifreq) *)((char *)pfreq + len);
    }
#endif
  }

  free (ifc.CNAME(ifc_buf));
  close (fd);
#endif /* HAVE_SIOCGIFCONF */

  return result;
}

static PyMethodDef methods[] = {
  { "ifaddresses", (PyCFunction)ifaddrs, METH_VARARGS,
    "Obtain information about the specified network interface.\n"
"\n"
"Returns a dict whose keys are equal to the address family constants,\n"
"e.g. netifaces.AF_INET, and whose values are a list of addresses in\n"
"that family that are attached to the network interface." },
  { "interfaces", (PyCFunction)interfaces, METH_NOARGS,
    "Obtain a list of the interfaces available on this machine." },
  { NULL, NULL, 0, NULL }
};

PyMODINIT_FUNC
initnetifaces (void)
{
  PyObject *address_family_dict;
  PyObject *m;

#ifdef WIN32
  WSADATA wsad;
  
  WSAStartup(MAKEWORD (2, 2), &wsad);
#endif

  m = Py_InitModule ("netifaces", methods);

  /* Address families (auto-detect using #ifdef) */
  address_family_dict = PyDict_New();
#ifdef AF_UNSPEC  
  PyModule_AddIntConstant (m, "AF_UNSPEC", AF_UNSPEC);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_UNSPEC),
          PyString_FromString("AF_UNSPEC"));
#endif
#ifdef AF_UNIX
  PyModule_AddIntConstant (m, "AF_UNIX", AF_UNIX);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_UNIX),
          PyString_FromString("AF_UNIX"));
#endif
#ifdef AF_FILE
  PyModule_AddIntConstant (m, "AF_FILE", AF_FILE);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_FILE),
          PyString_FromString("AF_FILE"));
#endif
#ifdef AF_INET
  PyModule_AddIntConstant (m, "AF_INET", AF_INET);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_INET),
          PyString_FromString("AF_INET"));
#endif
#ifdef AF_AX25
  PyModule_AddIntConstant (m, "AF_AX25", AF_AX25);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_AX25),
          PyString_FromString("AF_AX25"));
#endif
#ifdef AF_IMPLINK  
  PyModule_AddIntConstant (m, "AF_IMPLINK", AF_IMPLINK);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_IMPLINK),
          PyString_FromString("AF_IMPLINK"));
#endif
#ifdef AF_PUP  
  PyModule_AddIntConstant (m, "AF_PUP", AF_PUP);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_PUP),
          PyString_FromString("AF_PUP"));
#endif
#ifdef AF_CHAOS
  PyModule_AddIntConstant (m, "AF_CHAOS", AF_CHAOS);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_CHAOS),
          PyString_FromString("AF_CHAOS"));
#endif
#ifdef AF_NS
  PyModule_AddIntConstant (m, "AF_NS", AF_NS);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_NS),
          PyString_FromString("AF_NS"));
#endif
#ifdef AF_ISO
  PyModule_AddIntConstant (m, "AF_ISO", AF_ISO);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_ISO),
          PyString_FromString("AF_ISO"));
#endif
#ifdef AF_ECMA
  PyModule_AddIntConstant (m, "AF_ECMA", AF_ECMA);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_ECMA),
          PyString_FromString("AF_ECMA"));
#endif
#ifdef AF_DATAKIT
  PyModule_AddIntConstant (m, "AF_DATAKIT", AF_DATAKIT);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_DATAKIT),
          PyString_FromString("AF_DATAKIT"));
#endif
#ifdef AF_CCITT
  PyModule_AddIntConstant (m, "AF_CCITT", AF_CCITT);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_CCITT),
          PyString_FromString("AF_CCITT"));
#endif
#ifdef AF_SNA
  PyModule_AddIntConstant (m, "AF_SNA", AF_SNA);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_SNA),
          PyString_FromString("AF_SNA"));
#endif
#ifdef AF_DECnet
  PyModule_AddIntConstant (m, "AF_DECnet", AF_DECnet);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_DECnet),
          PyString_FromString("AF_DECnet"));
#endif
#ifdef AF_DLI
  PyModule_AddIntConstant (m, "AF_DLI", AF_DLI);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_DLI),
          PyString_FromString("AF_DLI"));
#endif
#ifdef AF_LAT
  PyModule_AddIntConstant (m, "AF_LAT", AF_LAT);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_LAT),
          PyString_FromString("AF_LAT"));
#endif
#ifdef AF_HYLINK
  PyModule_AddIntConstant (m, "AF_HYLINK", AF_HYLINK);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_HYLINK),
          PyString_FromString("AF_HYLINK"));
#endif
#ifdef AF_APPLETALK
  PyModule_AddIntConstant (m, "AF_APPLETALK", AF_APPLETALK);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_APPLETALK),
          PyString_FromString("AF_APPLETALK"));
#endif
#ifdef AF_ROUTE
  PyModule_AddIntConstant (m, "AF_ROUTE", AF_ROUTE);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_ROUTE),
          PyString_FromString("AF_ROUTE"));
#endif
#ifdef AF_LINK
  PyModule_AddIntConstant (m, "AF_LINK", AF_LINK);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_LINK),
          PyString_FromString("AF_LINK"));
#endif
#ifdef AF_PACKET
  PyModule_AddIntConstant (m, "AF_PACKET", AF_PACKET);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_PACKET),
          PyString_FromString("AF_PACKET"));
#endif
#ifdef AF_COIP
  PyModule_AddIntConstant (m, "AF_COIP", AF_COIP);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_COIP),
          PyString_FromString("AF_COIP"));
#endif
#ifdef AF_CNT
  PyModule_AddIntConstant (m, "AF_CNT", AF_CNT);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_CNT),
          PyString_FromString("AF_CNT"));
#endif
#ifdef AF_IPX
  PyModule_AddIntConstant (m, "AF_IPX", AF_IPX);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_IPX),
          PyString_FromString("AF_IPX"));
#endif
#ifdef AF_SIP
  PyModule_AddIntConstant (m, "AF_SIP", AF_SIP);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_SIP),
          PyString_FromString("AF_SIP"));
#endif
#ifdef AF_NDRV
  PyModule_AddIntConstant (m, "AF_NDRV", AF_NDRV);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_NDRV),
          PyString_FromString("AF_NDRV"));
#endif
#ifdef AF_ISDN
  PyModule_AddIntConstant (m, "AF_ISDN", AF_ISDN);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_ISDN),
          PyString_FromString("AF_ISDN"));
#endif
#ifdef AF_INET6
  PyModule_AddIntConstant (m, "AF_INET6", AF_INET6);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_INET6),
          PyString_FromString("AF_INET6"));
#endif
#ifdef AF_NATM
  PyModule_AddIntConstant (m, "AF_NATM", AF_NATM);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_NATM),
          PyString_FromString("AF_NATM"));
#endif
#ifdef AF_SYSTEM
  PyModule_AddIntConstant (m, "AF_SYSTEM", AF_SYSTEM);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_SYSTEM),
          PyString_FromString("AF_SYSTEM"));
#endif
#ifdef AF_NETBIOS
  PyModule_AddIntConstant (m, "AF_NETBIOS", AF_NETBIOS);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_NETBIOS),
          PyString_FromString("AF_NETBIOS"));
#endif
#ifdef AF_NETBEUI
  PyModule_AddIntConstant (m, "AF_NETBEUI", AF_NETBEUI);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_NETBEUI),
          PyString_FromString("AF_NETBEUI"));
#endif
#ifdef AF_PPP
  PyModule_AddIntConstant (m, "AF_PPP", AF_PPP);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_PPP),
          PyString_FromString("AF_PPP"));
#endif
#ifdef AF_ATM
  PyModule_AddIntConstant (m, "AF_ATM", AF_ATM);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_ATM),
          PyString_FromString("AF_ATM"));
#endif
#ifdef AF_ATMPVC
  PyModule_AddIntConstant (m, "AF_ATMPVC", AF_ATMPVC);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_ATMPVC),
          PyString_FromString("AF_ATMPVC"));
#endif
#ifdef AF_ATMSVC
  PyModule_AddIntConstant (m, "AF_ATMSVC", AF_ATMSVC);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_ATMSVC),
          PyString_FromString("AF_ATMSVC"));
#endif
#ifdef AF_NETGRAPH
  PyModule_AddIntConstant (m, "AF_NETGRAPH", AF_NETGRAPH);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_NETGRAPH),
          PyString_FromString("AF_NETGRAPH"));
#endif
#ifdef AF_VOICEVIEW
  PyModule_AddIntConstant (m, "AF_VOICEVIEW", AF_VOICEVIEW);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_VOICEVIEW),
          PyString_FromString("AF_VOICEVIEW"));
#endif
#ifdef AF_FIREFOX
  PyModule_AddIntConstant (m, "AF_FIREFOX", AF_FIREFOX);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_FIREFOX),
          PyString_FromString("AF_FIREFOX"));
#endif
#ifdef AF_UNKNOWN1
  PyModule_AddIntConstant (m, "AF_UNKNOWN1", AF_UNKNOWN1);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_UNKNOWN1),
          PyString_FromString("AF_UNKNOWN1"));
#endif
#ifdef AF_BAN
  PyModule_AddIntConstant (m, "AF_BAN", AF_BAN);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_BAN),
          PyString_FromString("AF_BAN"));
#endif
#ifdef AF_CLUSTER
  PyModule_AddIntConstant (m, "AF_CLUSTER", AF_CLUSTER);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_CLUSTER),
          PyString_FromString("AF_CLUSTER"));
#endif
#ifdef AF_12844
  PyModule_AddIntConstant (m, "AF_12844", AF_12844);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_12844),
          PyString_FromString("AF_12844"));
#endif
#ifdef AF_IRDA
  PyModule_AddIntConstant (m, "AF_IRDA", AF_IRDA);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_IRDA),
          PyString_FromString("AF_IRDA"));
#endif
#ifdef AF_NETDES
  PyModule_AddIntConstant (m, "AF_NETDES", AF_NETDES);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_NETDES),
          PyString_FromString("AF_NETDES"));
#endif
#ifdef AF_NETROM
  PyModule_AddIntConstant (m, "AF_NETROM", AF_NETROM);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_NETROM),
          PyString_FromString("AF_NETROM"));
#endif
#ifdef AF_BRIDGE
  PyModule_AddIntConstant (m, "AF_BRIDGE", AF_BRIDGE);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_BRIDGE),
          PyString_FromString("AF_BRIDGE"));
#endif
#ifdef AF_X25
  PyModule_AddIntConstant (m, "AF_X25", AF_X25);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_X25),
          PyString_FromString("AF_X25"));
#endif
#ifdef AF_ROSE
  PyModule_AddIntConstant (m, "AF_ROSE", AF_ROSE);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_ROSE),
          PyString_FromString("AF_ROSE"));
#endif
#ifdef AF_SECURITY
  PyModule_AddIntConstant (m, "AF_SECURITY", AF_SECURITY);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_SECURITY),
          PyString_FromString("AF_SECURITY"));
#endif
#ifdef AF_KEY
  PyModule_AddIntConstant (m, "AF_KEY", AF_KEY);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_KEY),
          PyString_FromString("AF_KEY"));
#endif
#ifdef AF_NETLINK
  PyModule_AddIntConstant (m, "AF_NETLINK", AF_NETLINK);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_NETLINK),
          PyString_FromString("AF_NETLINK"));
#endif
#ifdef AF_ASH
  PyModule_AddIntConstant (m, "AF_ASH", AF_ASH);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_ASH),
          PyString_FromString("AF_ASH"));
#endif
#ifdef AF_ECONET
  PyModule_AddIntConstant (m, "AF_ECONET", AF_ECONET);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_ECONET),
          PyString_FromString("AF_ECONET"));
#endif
#ifdef AF_SNA
  PyModule_AddIntConstant (m, "AF_SNA", AF_SNA);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_SNA),
          PyString_FromString("AF_SNA"));
#endif
#ifdef AF_PPPOX
  PyModule_AddIntConstant (m, "AF_PPPOX", AF_PPPOX);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_PPPOX),
          PyString_FromString("AF_PPPOX"));
#endif
#ifdef AF_WANPIPE
  PyModule_AddIntConstant (m, "AF_WANPIPE", AF_WANPIPE);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_WANPIPE),
          PyString_FromString("AF_WANPIPE"));
#endif
#ifdef AF_BLUETOOTH
  PyModule_AddIntConstant (m, "AF_BLUETOOTH", AF_BLUETOOTH);
  PyDict_SetItem(address_family_dict, PyInt_FromLong(AF_BLUETOOTH),
          PyString_FromString("AF_BLUETOOTH"));
#endif
  PyModule_AddObject(m, "address_families", address_family_dict);

  // Add-in the version number from setup.py
#define _STR(x) #x
#define STR(x)  _STR(x)

  PyModule_AddStringConstant(m, "version", STR(NETIFACES_VERSION));
}
