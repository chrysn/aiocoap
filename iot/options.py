from itertools import chain

from .numbers import *

def readExtendedFieldValue(value, rawdata):
    """Used to decode large values of option delta and option length
       from raw binary form."""
    if value >= 0 and value < 13:
        return (value, rawdata)
    elif value == 13:
        return (rawdata[0] + 13, rawdata[1:])
    elif value == 14:
        return (struct.unpack('!H', rawdata[:2])[0] + 269, rawdata[2:])
    else:
        raise ValueError("Value out of range.")


def writeExtendedFieldValue(value):
    """Used to encode large values of option delta and option length
       into raw binary form.
       In CoAP option delta and length can be represented by a variable
       number of bytes depending on the value."""
    if value >= 0 and value < 13:
        return (value, b'')
    elif value >= 13 and value < 269:
        return (13, struct.pack('!B', value - 13))
    elif value >= 269 and value < 65804:
        return (14, struct.pack('!H', value - 269))
    else:
        raise ValueError("Value out of range.")




class Options(object):
    """Represent CoAP Header Options."""
    def __init__(self):
        self._options = {}

    def decode(self, rawdata):
        """Decode all options in message from raw binary data."""
        option_number = OptionNumber(0)

        while len(rawdata) > 0:
            if rawdata[0] == 0xFF:
                return rawdata[1:]
            dllen = rawdata[0]
            delta = (dllen & 0xF0) >> 4
            length = (dllen & 0x0F)
            rawdata = rawdata[1:]
            (delta, rawdata) = readExtendedFieldValue(delta, rawdata)
            (length, rawdata) = readExtendedFieldValue(length, rawdata)
            option_number += delta
            option = option_number.create_option(decode=rawdata[:length])
            self.addOption(option)
            rawdata = rawdata[length:]
        return ''

    def encode(self):
        """Encode all options in option header into string of bytes."""
        data = []
        current_opt_num = 0
        option_list = self.optionList()
        for option in option_list:
            delta, extended_delta = writeExtendedFieldValue(option.number - current_opt_num)
            length, extended_length = writeExtendedFieldValue(option.length)
            data.append(bytes([((delta & 0x0F) << 4) + (length & 0x0F)]))
            data.append(extended_delta)
            data.append(extended_length)
            data.append(option.encode())
            current_opt_num = option.number
        return (b''.join(data))

    def addOption(self, option):
        """Add option into option header."""
        self._options.setdefault(option.number, []).append(option)

    def deleteOption(self, number):
        """Delete option from option header."""
        if number in self._options:
            self._options.pop(number)

    def getOption (self, number):
        """Get option with specified number."""
        return self._options.get(number)

    def optionList(self):
        return chain.from_iterable(sorted(self._options.values(), key=lambda x: x[0].number))

    def _setUriPath(self, segments):
        """Convenience setter: Uri-Path option"""
        if isinstance(segments, str): #For Python >3.1 replace with isinstance(segments,str)
            raise ValueError("URI Path should be passed as a list or tuple of segments")
        self.deleteOption(number=OptionNumber.URI_PATH)
        for segment in segments:
            self.addOption(OptionNumber.URI_PATH.create_option(value=str(segment)))

    def _getUriPath(self):
        """Convenience getter: Uri-Path option"""
        segment_list = []
        uri_path = self.getOption(number=OptionNumber.URI_PATH)
        if uri_path is not None:
            for segment in uri_path:
                segment_list.append(segment.value)
        return segment_list

    uri_path = property(_getUriPath, _setUriPath)

    def _setUriQuery(self, segments):
        """Convenience setter: Uri-Query option"""
        if isinstance(segments, str): #For Python >3.1 replace with isinstance(segments,str)
            raise ValueError("URI Query should be passed as a list or tuple of segments")
        self.deleteOption(number=OptionNumber.URI_QUERY)
        for segment in segments:
            self.addOption(OptionNumber.URI_QUERY.create_option(value=str(segment)))

    def _getUriQuery(self):
        """Convenience getter: Uri-Query option"""
        segment_list = []
        uri_query = self.getOption(number=OptionNumber.URI_QUERY)
        if uri_query is not None:
            for segment in uri_query:
                segment_list.append(segment.value)
        return segment_list

    uri_query = property(_getUriQuery, _setUriQuery)

    def _setBlock2(self, block_tuple):
        """Convenience setter: Block2 option"""
        self.deleteOption(number=OptionNumber.BLOCK2)
        self.addOption(BlockOption(number=OptionNumber.BLOCK2, value=block_tuple))

    def _getBlock2(self):
        """Convenience getter: Block2 option"""
        block2 = self.getOption(number=OptionNumber.BLOCK2)
        if block2 is not None:
            return block2[0].value
        else:
            return None

    block2 = property(_getBlock2, _setBlock2)

    def _setBlock1(self, block_tuple):
        """Convenience setter: Block1 option"""
        self.deleteOption(number=OptionNumber.BLOCK1)
        self.addOption(OptionNumber.BLOCK1.create_option(value=block_tuple))

    def _getBlock1(self):
        """Convenience getter: Block1 option"""
        block1 = self.getOption(number=OptionNumber.BLOCK1)
        if block1 is not None:
            return block1[0].value
        else:
            return None

    block1 = property(_getBlock1, _setBlock1)

    def _setContentFormat(self, content_format):
        """Convenience setter: Content-Format option"""
        self.deleteOption(number=OptionNumber.CONTENT_FORMAT)
        self.addOption(OptionNumber.CONTENT_FORMAT.create_option(value=content_format))

    def _getContentFormat(self):
        """Convenience getter: Content-Format option"""
        content_format = self.getOption(number=OptionNumber.CONTENT_FORMAT)
        if content_format is not None:
            return content_format[0].value
        else:
            return None

    content_format = property(_getContentFormat, _setContentFormat)

    def _setETag(self, etag):
        """Convenience setter: ETag option"""
        self.deleteOption(number=OptionNumber.ETAG)
        if etag is not None:
            self.addOption(OptionNumber.ETAG.create_option(value=etag))

    def _getETag(self):
        """Convenience getter: ETag option"""
        etag = self.getOption(number=OptionNumber.ETAG)
        if etag is not None:
            return etag[0].value
        else:
            return None

    etag = property(_getETag, _setETag, None, "Access to a single ETag on the message (as used in responses)")

    def _setETags(self, etags):
        self.deleteOption(number=OptionNumber.ETAG)
        for tag in etags:
            self.addOption(OptionNumber.ETAG.create_option(value=tag))

    def _getETags(self):
        etag = self.getOption(number=OptionNumber.ETAG)
        return [] if etag is None else [tag.value for tag in etag]

    etags = property(_getETags, _setETags, None, "Access to a list of ETags on the message (as used in requests)")

    # FIXME this is largely copy/paste

    def _setObserve(self, observe):
        self.deleteOption(number=OptionNumber.OBSERVE)
        if observe is not None:
            self.addOption(OptionNumber.OBSERVE.create_option(value=observe))

    def _getObserve(self):
        observe = self.getOption(number=OptionNumber.OBSERVE)
        if observe is not None:
            return observe[0].value
        else:
            return None

    observe = property(_getObserve, _setObserve)

    def _setAccept(self, accept):
        self.deleteOption(number=OptionNumber.ACCEPT)
        if accept is not None:
            self.addOption(UintOption(number=OptionNumber.ACCEPT, value=accept))

    def _getAccept(self):
        accept = self.getOption(number=OptionNumber.ACCEPT)
        if accept is not None:
            return accept[0].value
        else:
            return None

    accept = property(_getAccept, _setAccept)

    def _setUriHost(self, uri_host):
        self.deleteOption(number=OptionNumber.URI_HOST)
        if uri_host is not None:
            self.addOption(StringOption(number=OptionNumber.URI_HOST, value=uri_host))

    def _getUriHost(self):
        uri_host = self.getOption(number=OptionNumber.URI_HOST)
        if uri_host is not None:
            return uri_host[0].value
        else:
            return None

    uri_host = property(_getUriHost, _setUriHost)

    def _setUriPort(self, uri_port):
        self.deleteOption(number=OptionNumber.URI_PORT)
        if uri_port is not None:
            self.addOption(IntOption(number=OptionNumber.URI_PORT, value=uri_port))

    def _getUriPort(self):
        uri_port = self.getOption(number=OptionNumber.URI_PORT)
        if uri_port is not None:
            return uri_port[0].value
        else:
            return None

    uri_port = property(_getUriPort, _setUriPort)
