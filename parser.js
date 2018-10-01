function create_parser(fmt) {
  if (fmt == 'ivf') {
    return new file_parser_ivf();
  } else if (['264', 'h264', 'avc'].indexOf(fmt) >= 0) {
    return new file_parser_annexb('H264');
  } else if (['265', 'h265', 'hevc', 'bin'].indexOf(fmt) >= 0) {
    return new file_parser_annexb('H265');
  }
  return null;
}

function bitstream(buffer) {
  this.buffer = buffer;
  this.length = (buffer instanceof Array) ? buffer.length : buffer.byteLength;
  this.bytepos = 0;
  this.bits = 0;
  this.nbits = 0;

  var trailing_zero_bytes = 0;
  while (0 == this.buffer[this.length - 1 - trailing_zero_bytes]) {
    trailing_zero_bytes++;
  }

  var trailing_zero_bits = 0;
  while ((this.buffer[this.length - 1 - trailing_zero_bytes] &
          (1 << trailing_zero_bits)) == 0 &&
         trailing_zero_bits < 8) {
    trailing_zero_bits++;
  }

  this.stopbit = 8 * (this.length - trailing_zero_bytes) - trailing_zero_bits;

  this.load = function() {
    while (this.nbits <= 24 && this.bytepos < this.length) {
      var onebyte = this.buffer[this.bytepos++];
      this.bits |= onebyte << (24 - this.nbits);
      this.nbits += 8;
    }
  };

  this.bitpos = function() {
    return 8 * this.bytepos - this.nbits;
  };

  this.u = function(n) {
    var bits = 0;
    while (n) {
      bits <<= n;
      var r = n > 24 ? 24 : n;
      this.load();
      bits |= this.bits >>> (32 - r);
      this.bits <<= r;
      this.nbits -= r;
      n -= r;
    }
    return bits;
  };

  this.s = function(n) {
    var val = this.u(n);
    var sign = this.u(1);
    return sign ? -val : val;
  };

  this.ue = function() {
    this.load();
    var bits = this.bits | 1;
    var leadingzeros = 0;
    while (!(bits & (1 << 31))) {
      bits <<= 1;
      leadingzeros++;
    }
    this.bits <<= leadingzeros;
    this.nbits -= leadingzeros;
    return this.u(leadingzeros + 1) - 1;
  };

  this.se = function() {
    var codenum = this.ue();
    var codeval = (codenum + 1) >> 1;
    return (codenum & 1) ? codeval : -codeval;
  };
}

function int2str(x, base, length, padding, padend) {
  var str = x.toString(base);
  var pad = Array(length - str.length + 1).join(padding);
  return padend ? str + pad : pad + str;
}

function cntbits(x) {
  var nbits = 1;
  while (1 << nbits < x) nbits++;
  return nbits;
}

function more_rbsp_data(bs) {
  return bs.bitpos() + 1 < bs.stopbit;
}

function bytes2str(bytes) {
  var str = '';
  for (var i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
  return str;
}

function bytes2word(buffer, offset) {
  return (buffer[offset + 1] << 8) | buffer[offset + 0];
}

function bytes2dword(buffer, offset) {
  return (buffer[offset + 3] << 24) | (buffer[offset + 2] << 16) |
      (buffer[offset + 1] << 8) | buffer[offset];
}

function in_range(x, array) {
  return array.indexOf(x) > -1 ? 1 : 0;
}

function file_parser_base() {
  this.parser = 0;
  this.buffer = new Uint8Array(1024 * 1024);
  this.recv = 0;
  this.addr = 0;
  this.header = [];
  this.last = 0;
  this.idoff = 1000000;

  this.store = function(h) {
    h['@id'] = this.header.length;
    this.header.push(h);
  };

  this.next = function() {
    if (this.last < this.header.length) return this.header[this.last++];
    if (this.parser) return this.parser.next();
    return null;
  };

  this.get = function(id) {
    if (id >= this.idoff) return this.parser.get(id);
    return this.header[id];
  };
}

function file_parser_ivf() {
  file_parser_base.call(this);
  this.goto = 2;
  this.need = 8;
}

file_parser_ivf.prototype = new file_parser_base();
file_parser_ivf.prototype.parse = function(buffer) {
  if (buffer == null) {
    return;
  }
  var pos = 0;
  while (pos < buffer.length) {
    if (this.need > 0) {
      this.buffer[this.recv++] = buffer[pos++];
      this.need--;
    }
    if (this.need) continue;

    if (this.goto == 0) {
      this.parser.parse(this.buffer.slice(0, this.recv), this.addr);
      this.need = 12;
      this.goto = 1;
    } else if (this.goto == 1) {
      this.need = bytes2dword(this.buffer, 0);
      this.goto = 0;
    } else if (this.goto == 2) {
      this.need = bytes2word(this.buffer, 6) - 8;
      this.goto = 3;
      continue;
    } else if (this.goto == 3) {
      var h = this.ivf_header(this.buffer, this.addr);
      if (h['fourcc'] == 'VP80')
        this.parser = new bitstream_parser_vp8(this.idoff);
      else if (h['fourcc'] == 'VP90')
        this.parser = new bitstream_parser_vp9(this.idoff);
      else if (h['fourcc'] == 'AV01')
        this.parser = new bitstream_parser_av1(this.idoff);
      else if (h['fourcc'] == 'H264')
        this.parser = new file_parser_annexb('H264');
      else
        alert('unknown fourcc ' + h['fourcc']);
      this.store(h);
      this.need = 12;
      this.goto = 1;
    }
    this.addr += this.recv;
    this.recv = 0;
  }
};

file_parser_ivf.prototype.ivf_header = function(buffer, addr) {
  var h = {};
  h['signature'] = bytes2str(buffer.slice(0, 4));
  h['version'] = bytes2word(buffer, 4);
  h['length'] = bytes2word(buffer, 6);
  h['fourcc'] = bytes2str(buffer.slice(8, 12));
  h['width'] = bytes2word(buffer, 12);
  h['height'] = bytes2word(buffer, 14);
  h['frame rate'] = bytes2dword(buffer, 16);
  h['time scale'] = bytes2dword(buffer, 20);
  h['num frames'] = bytes2dword(buffer, 24);
  h['@addr'] = addr;
  h['@type'] = 'IVF';
  h['@length'] = h['length'];
  h['@extra'] = h['fourcc'] + ' ' + h['width'] + 'x' + h['height'];
  return h;
};

function file_parser_annexb(fourcc) {
  file_parser_base.call(this);
  this.code = 0xffffffff;
  this.first = true;
  if (fourcc == 'H264') {
    this.parser = new bitstream_parser_h264(this.idoff);
  } else if (fourcc == 'H265') {
    this.parser = new bitstream_parser_h265(this.idoff);
  }
}

file_parser_annexb.prototype = new file_parser_base();
file_parser_annexb.prototype.parse = function(buffer, addr) {
  if (buffer == null) {
    this.parse(new Uint8Array([0, 0, 1]), addr);
  } else {
    var pos = 0;
    if (this.first) {
      while (pos < buffer.length) {
        var byte = buffer[pos++];
        this.addr++;
        this.code = (this.code << 8) | byte;
        if ((this.code & 0x00ffffff) == 1) {
          this.first = false;
          break;
        }
      }
    }

    var cnt3 = 0;
    while (pos < buffer.length) {
      var byte = buffer[pos++];
      var code = (this.code = (this.code << 8) | byte) & 0x00ffffff;
      if (code == 3) {
        cnt3++;
      } else {
        this.buffer[this.recv++] = byte;
        if (code == 1) {
          this.recv -= 3;
          this.parser.parse(this.buffer.slice(0, this.recv), this.addr);
          this.addr += this.recv + cnt3;
          this.recv = 0;
          cnt3 = 0;
        }
      }
    }
  }
};

function bitstream_parser_base(idoff) {
  this.idoff = idoff;
  this.header = [];
  this.last = 0;

  this.next = function() {
    if (this.last < this.header.length) return this.header[this.last++];
    return null;
  };

  this.get = function(id) {
    return this.header[id - this.idoff];
  };

  this.store = function(h) {
    h['@id'] = this.header.length + this.idoff;
    this.header.push(h);
  };
}

function bitstream_parser_vp8(idoff) {
  bitstream_parser_base.call(this, idoff);
}

bitstream_parser_vp8.prototype = new bitstream_parser_base();
bitstream_parser_vp8.prototype.parse = function(buffer, addr) {
  var bs = new bitstream(buffer);
  var h = {};
  var byte = bs.u(8);
  h['frame_type'] = byte & 1;
  h['version'] = (byte >> 1) & 7;
  h['show_frame'] = (byte >> 4) & 1;
  h['partition_length'] = (byte | (bs.u(8) << 8) | (bs.u(8) << 16)) >> 5;
  if (h['frame_type'] == 0) {
    h['sync_code'] = '0x' + int2str(bs.u(24), 16, 6, 0, 0);
    h['width'] = (bs.u(8) | (bs.u(8) << 8)) & 0x3fff;
    h['height'] = (bs.u(8) | (bs.u(8) << 8)) & 0x3fff;
  }
  h['@addr'] = addr;
  h['@type'] = h['frame_type'] == 0 ? 'I' : 'P';
  h['@length'] = buffer.length;
  h['@keyframe'] = 1 - h['frame_type'];
  this.store(h);
};

function bitstream_parser_vp9(idoff) {
  bitstream_parser_base.call(this, idoff);
}

bitstream_parser_vp9.prototype = new bitstream_parser_base();
bitstream_parser_vp9.prototype.parse = function(buffer, addr) {
  var bs = new bitstream(buffer);
  var h = {};
  var ref_idx = 0;
  h['frame_marker'] = bs.u(2);
  h['profile'] = bs.u(1) + (bs.u(1) << 1);
  if (h['profile'] == 3) h['reserved_zero'] = bs.u(1);
  h['show_existing_frames'] = bs.u(1);
  if (h['show_existing_frames']) h['frame_to_show_map_idx'] = bs.u(3);
  h['frame_type'] = bs.u(1);
  h['show_frame'] = bs.u(1);
  h['error_resilient_mode'] = bs.u(1);
  if (h['frame_type'] == 0) {
    h['frame_sync_bytes'] = bs.u(8) + ', ' + bs.u(8) + ', ' + bs.u(8);
    this.color_config(h, bs);
    h['frame_width_minus_1'] = bs.u(16);
    h['frame_height_minus_1'] = bs.u(16);
    h['render_and_frame_size_different'] = bs.u(1);
    if (h['render_and_frame_size_different'] == 1) {
      h['render_width_minus_1'] = bs.u(16);
      h['render_height_minus_1'] = bs.u(16);
    }
  } else {
    if (h['show_frame'] == 0) h['intra_only'] = bs.u(1);
    if (h['error_resilient_mode'] == 0) h['reset_frame_context'] = bs.u(2);
    if (h['intra_only'] || 0) {
      h['frame_sync_bytes'] = bs.u(8) + ', ' + bs.u(8) + ', ' + bs.u(8);
      if (h['profile'] > 0) {
        this.color_config(h, bs);
        h['refresh_frame_flags'] = int2str(bs.u(8), 2, 8, '0', 0);
        h['frame_width_minus_1'] = bs.u(16);
        h['frame_height_minus_1'] = bs.u(16);
        h['render_and_frame_size_different'] = bs.u(1);
        if (h['render_and_frame_size_different'] == 1) {
          h['render_width_minus_1'] = bs.u(16);
          h['render_height_minus_1'] = bs.u(16);
        }
      }
    } else {
      h['refresh_frame_flags'] = int2str(bs.u(8), 2, 8, '0', 0);
      for (var i = 0; i < 3; i++) {
        h['ref_frame_idx[' + i + ']'] = bs.u(3);
        h['ref_frame_sign_bias[' + i + ']'] = bs.u(1);
      }
      for (ref_idx = 0; ref_idx < 3; ref_idx++) {
        h['size_in_refs'] = bs.u(1);
        if (h['size_in_refs']) break;
      }
      if (h['size_in_refs'] == 0) {
        h['frame_width_minus_1'] = bs.u(16);
        h['frame_height_minus_1'] = bs.u(16);
      }
      h['render_and_frame_size_different'] = bs.u(1);
      if (h['render_and_frame_size_different'] == 1) {
        h['render_width_minus_1'] = bs.u(16);
        h['render_height_minus_1'] = bs.u(16);
      }
      h['allow_high_precision_mv'] = bs.u(1);
      h['is_filter_switchable'] = bs.u(1);
      if (h['is_filter_switchable'] == 0)
        h['raw_interpolation_filter'] = bs.u(2);
    }
  }

  if (h['error_resilient_mode'] == 0) {
    h['refresh_frame_context'] = bs.u(1);
    h['frame_parallel_decoding_mode'] = bs.u(1);
  }
  h['frame_context_idx'] = bs.u(2);
  h['loop_filter_level'] = bs.u(6);
  h['loop_filter_sharpness'] = bs.u(3);
  h['loop_filter_delta_enabled'] = bs.u(1);
  if (h['loop_filter_delta_enabled'] == 1) {
    h['loop_filter_delta_update'] = bs.u(1);
    if (h['loop_filter_delta_update'] == 1) {
      for (var i = 0; i < 4; i++) {
        h['update_ref_delta[' + i + ']'] = bs.u(1);
        if (h['update_ref_delta[' + i + ']'] == 1)
          h['loop_filter_ref_deltas[' + i + ']'] = bs.s(6);
      }
      for (var i = 0; i < 2; i++) {
        h['update_mode_delta[' + i + ']'] = bs.u(1);
        if (h['update_mode_delta[' + i + ']'] == 1)
          h['loop_filter_mode_deltas[[' + i + ']'] = bs.s(6);
      }
    }
  }
  h['base_q_idx'] = bs.u(8);
  for (var i = 0; i < 3; i++) {
    h['delta_coded[' + i + ']'] = bs.u(1);
    if (h['delta_coded[' + i + ']']) h['delta_q[' + i + ']'] = bs.s(4);
  }

  if ('frame_width_minus_1' in h) {
    h['@FrameWidth'] = h['frame_width_minus_1'] + 1;
    h['@FrameHeight'] = h['frame_height_minus_1'] + 1;
  } else {
    var ref = this.find_ref(h['ref_frame_idx[' + ref_idx + ']']);
    if (ref) {
      h['@FrameWidth'] = ref['@FrameWidth'];
      h['@FrameHeight'] = ref['@FrameHeight'];
    }
  }
  var MiCols = (h['@FrameWidth'] + 7) >> 3;
  var MiRows = (h['@FrameHeight'] + 7) >> 3;
  var Sb64Cols = (MiCols + 7) >> 3;
  var Sb64Rows = (MiRows + 7) >> 3;
  var minLog2TileCols = 0;
  while ((64 << minLog2TileCols) < Sb64Cols) minLog2TileCols++;
  var maxLog2TileCols = 0;
  while ((Sb64Cols >> (maxLog2TileCols + 1)) >= 4) maxLog2TileCols++;
  var tile_cols_log2 = minLog2TileCols;
  for (var i = 0; tile_cols_log2 < maxLog2TileCols; i++) {
    h['increment_tile_cols_log2[' + i + ']'] = bs.u(1);
    if (h['increment_tile_cols_log2[' + i + ']'])
      tile_cols_log2++;
    else
      break;
  }
  h['tile_rows_log2'] = bs.u(1);
  if (h['tile_rows_log2']) h['increment_tile_rows_log2'] = bs.u(1);

  h['header_size_in_bytes'] = bs.u(16);

  h['@addr'] = addr;
  h['@type'] = h['frame_type'] == 0 ? 'I' : 'P';
  h['@length'] = buffer.length;
  h['@keyframe'] = 1 - h['frame_type'];
  h['@extra'] = int2str(h['@FrameWidth'], 10, 4, ' ', 0) + 'x' +
      int2str(h['@FrameHeight'], 10, 4, ' ', 1) + ' QP ' +
      int2str(h['base_q_idx'], 10, 3, ' ', 0);
  h['@extra'] += ' upd ' +
      ('refresh_frame_flags' in h ? h['refresh_frame_flags'] : '11111111');
  if ('ref_frame_idx[0]' in h) {
    var ref_mask = (1 << h['ref_frame_idx[0]']) | (1 << h['ref_frame_idx[1]']) |
        (1 << h['ref_frame_idx[2]']);
    h['@extra'] += ' ref ' + int2str(ref_mask, 2, 8, '0', 0);
  }
  this.store(h);
};

bitstream_parser_vp9.prototype.color_config = function(h, bs) {
  var color_space = {
    0: 'CS_UNKNOWN',
    1: 'CS_BT_601',
    2: 'CS_BT_709',
    3: 'CS_SMPTE_170',
    4: 'CS_SMPTE_240',
    5: 'CS_BT_2020',
    6: 'CS_RESERVED',
    7: 'CS_BT_601'
  };

  if (h['profile'] >= 2) h['ten_or_twelve_bit'] = bs.u(1);
  h['color_space'] = color_space[bs.u(3)];
  if (h['color_space'] != 'CS_RGB') h['color_range'] = bs.u(1);
  if (h['profile'] == 1 || h['profile'] == 3) {
    if (h['color_space'] != 'CS_RGB') {
      h['subsampling_x'] = bs.u(1);
      h['subsampling_y'] = bs.u(1);
    }
    h['reserved_zero'] = bs.u(1);
  }
};

bitstream_parser_vp9.prototype.find_ref = function(idx) {
  for (var i = this.header.length - 1; i >= 0; i--) {
    if (!('refresh_frame_flags' in this.header[i]) ||
        this.header[i]['refresh_frame_flags'] & (1 << idx))
      return this.header[i];
  }
  return null;
};

function bitstream_parser_av1(idoff) {
  bitstream_parser_base.call(this, idoff);
}

bitstream_parser_av1.prototype = new bitstream_parser_base();
bitstream_parser_av1.prototype.parse = function(buffer, addr) {
  var bs = new bitstream(buffer);
  var h = {};
  h['frame_marker'] = bs.u(2);
  h['profile'] = bs.u(2);
  if (h['profile'] > 2) h['profile'] += bs.u(1);
  h['show_existing_frames'] = bs.u(1);
  if (h['show_existing_frames']) h['frame_to_show_map_idx'] = bs.u(3);
  h['frame_type'] = bs.u(1);
  h['show_frame'] = bs.u(1);
  h['error_resilient_mode'] = bs.u(1);
  h['current_frame_id'] = bs.u(15);
  h['@addr'] = addr;
  h['@type'] = h['frame_type'] == 0 ? 'I' : 'P';
  h['@length'] = buffer.length;
  h['@keyframe'] = 1 - h['frame_type'];
  this.store(h);
};

function bitstream_parser_h264(idoff) {
  bitstream_parser_base.call(this, idoff);
  this.nal_unit_type = [
    'Unknown',
    'Slice',
    'DP A',
    'DP B',
    'DP C',
    'IDR',
    'SEI',
    'SPS',
    'PPS',
    'AUD',
    'End of sequence',
    'End of stream',
    'Filler data',
    'SPS extension',
    'Prefix NAL unit',
    'Subset SPS',
    'Reserved',
    'Reserved',
    'Reserved',
    'Auxiliary slice',
    'Slice extension',
    'Slice multiview',
    'Reserved',
    'Reserved',
    'Unknown',
    'Unknown',
    'Unknown',
    'Unknown',
    'Unknown',
    'Unknown',
    'Unknown',
    'Unknown'
  ];

  this.sei_payload_type = [
    'buffering_period', 'pic_timing', 'pan_scan_rect', 'filler_payload',
    'user_data_registered_itu_t_t35', 'user_data_unregistered',
    'recovery_point', 'dec_ref_pic_marking_repetition'
  ];
}

bitstream_parser_h264.prototype = new bitstream_parser_base();
bitstream_parser_h264.prototype.parse = function(buffer, addr) {
  var bs = new bitstream(buffer);
  var h = this.parse_nalu(bs);
  if (h['nal_unit_type'] == 6) {
    this.parse_sei(bs, h);
  } else if (h['nal_unit_type'] == 7) {
    this.parse_sps(bs, h);
    h['@extra'] = (h['pic_width_in_mbs_minus1'] + 1) * 16 + 'x' +
        (2 - h['frame_mbs_only_flag']) *
            (h['pic_height_in_map_units_minus1'] + 1) * 16;
    h['@extra'] += ' ' + this.profile(h);
    h['@extra'] += ' ' + h['level_idc'] / 10;
  } else if (h['nal_unit_type'] == 8) {
    this.parse_pps(bs, h);
    h['@extra'] = h['entropy_coding_mode_flag'] ? 'CABAC' : 'CAVLC';
  } else if (in_range(h['nal_unit_type'], [1, 5, 20])) {
    this.parse_slice(bs, h);
    h['@keyframe'] = h['nal_unit_type'] == 5 || (h['idr_flag'] || 0);
    if (h['@keyframe'])
      h['@type'] = 'IDR';
    else
      h['@type'] = ['P', 'B', 'I', 'SP', 'SI'][h['slice_type'] % 5];
  }
  h['@addr'] = addr;
  if (!('@type' in h)) h['@type'] = this.nal_unit_type[h['nal_unit_type']];
  h['@length'] = buffer.length;
  this.store(h);
};

bitstream_parser_h264.prototype.find_nalu = function(type, key, value) {
  for (var i = this.header.length - 1; i >= 0; i--) {
    if (in_range(this.header[i]['nal_unit_type'], type)) {
      if (key == null)
        return this.header[i];
      else if (this.header[i][key] == value)
        return this.header[i];
    }
  }
  return null;
};

bitstream_parser_h264.prototype.profile = function(sps) {
  var profile_idc = {
    66: 'Baseline',
    77: 'Main',
    88: 'Extended',
    100: 'High',
    110: 'High 10',
    122: 'High 4:2:2',
    244: 'High 4:4:4 Predictive',
    83: 'Scalable Baseline',
    86: 'Scalable High'
  };

  profile = sps['profile_idc'] in profile_idc ?
      profile_idc[sps['profile_idc']] :
      'Unknown';
  if (sps['profile_idc'] == 66) {
    if (sps['constraint_set0_flag'] == 1) profile = 'Constrained ' + profile;
  } else if (sps['profile_idc'] == 100) {
    if ((sps['constraint_set4_flag'] == 1 && sps['constraint_set5_flag'] == 1))
      profile = 'Constrained ' + profile;
  } else if (sps['profile_idc'] == 110) {
    if (sps['constraint_set3_flag'] == 1) profile += ' Intra';
  } else if (sps['profile_idc'] == 83) {
    if (sps['constraint_set5_flag'] == 1)
      profile = 'Scalable Constrained Baseline';
  } else if (sps['profile_idc'] == 86) {
    if (sps['constraint_set5_flag'] == 1) profile = 'Scalable Constrained High';
  }
  return profile;
};

bitstream_parser_h264.prototype.parse_nalu = function(bs) {
  var nalu = {};
  nalu['forbidden_zero_bit'] = bs.u(1);
  nalu['nal_ref_idc'] = bs.u(2);
  nalu['nal_unit_type'] = bs.u(5);
  if (in_range(nalu['nal_unit_type'], [14, 20, 30])) {
    nalu['svc_extension_flag'] = bs.u(1);
    if (nalu['svc_extension_flag']) {
      nalu['idr_flag'] = bs.u(1);
      nalu['priority_id'] = bs.u(6);
      nalu['no_inter_layer_pred_flag'] = bs.u(1);
      nalu['dependency_id'] = bs.u(3);
      nalu['quality_id'] = bs.u(4);
      nalu['temporal_id'] = bs.u(3);
      nalu['use_ref_base_pic_flag'] = bs.u(1);
      nalu['discardable_flag'] = bs.u(1);
      nalu['output_flag'] = bs.u(1);
      nalu['reserved_three_2bits'] = int2str(bs.u(2), 2, 2, '0', 0);
    }
  }
  return nalu;
};

bitstream_parser_h264.prototype.parse_sps = function(bs, sps) {
  sps['profile_idc'] = bs.u(8);
  sps['constraint_set0_flag'] = bs.u(1);
  sps['constraint_set1_flag'] = bs.u(1);
  sps['constraint_set2_flag'] = bs.u(1);
  sps['constraint_set3_flag'] = bs.u(1);
  sps['constraint_set4_flag'] = bs.u(1);
  sps['constraint_set5_flag'] = bs.u(1);
  sps['reserved_zero_2bits'] = int2str(bs.u(2), 2, 2, '0', 0);
  sps['level_idc'] = bs.u(8);
  sps['seq_parameter_set_id'] = bs.ue();
  if (in_range(
          sps['profile_idc'], [100, 110, 122, 244, 44, 83, 86, 118, 128])) {
    sps['chroma_format_idc'] = bs.ue();
    if (sps['chroma_format_idc'] == 3)
      sps['separate_colour_plane_flag'] = bs.u(1);
    sps['bit_depth_luma_minus8'] = bs.ue();
    sps['bit_depth_chroma_minus8'] = bs.ue();
    sps['qpprime_y_zero_transform_bypass_flag'] = bs.u(1);
    sps['seq_scaling_matrix_present_flag'] = bs.u(1);
    if (sps['seq_scaling_matrix_present_flag']) {
      for (var i = 0; i < (sps['chroma_format_idc'] != 3 ? 8 : 12); i++) {
        sps['seq_scaling_list_present_flag[' + i + ']'] = bs.u(1);
        if (sps['seq_scaling_list_present_flag[' + i + ']']) {
          var n = i < 6 ? 4 : 8;
          sps['seq_scaling_list_present_flag[' + i + ']'] =
              this.scaling_list(bs, n * n);
        }
      }
    }
  }
  sps['log2_max_frame_num_minus4'] = bs.ue();
  sps['pic_order_cnt_type'] = bs.ue();
  if (sps['pic_order_cnt_type'] == 0) {
    sps['log2_max_pic_order_cnt_lsb_minus4'] = bs.ue();
  } else if (sps['pic_order_cnt_type'] == 1) {
    sps['delta_pic_order_always_zero_flag'] = bs.u(1);
    sps['offset_for_non_ref_pic'] = bs.se();
    sps['offset_for_top_to_bottom_field'] = bs.se();
    sps['num_ref_frames_in_pic_order_cnt_cycle'] = bs.ue();
    for (var i = 0; i < sps['num_ref_frames_in_pic_order_cnt_cycle']; i++)
      sps['offset_for_ref_frame[' + i + ']'] = bs.se();
  }
  sps['max_num_ref_frames'] = bs.ue();
  sps['gaps_in_frame_num_value_allowed_flag'] = bs.u(1);
  sps['pic_width_in_mbs_minus1'] = bs.ue();
  sps['pic_height_in_map_units_minus1'] = bs.ue();
  sps['frame_mbs_only_flag'] = bs.u(1);
  if (sps['frame_mbs_only_flag'] == 0)
    sps['mb_adaptive_frame_field_flag'] = bs.u(1);
  sps['direct_8x8_inference_flag'] = bs.u(1);
  sps['frame_cropping_flag'] = bs.u(1);
  if (sps['frame_cropping_flag']) {
    sps['frame_crop_left_offset'] = bs.ue();
    sps['frame_crop_right_offset'] = bs.ue();
    sps['frame_crop_top_offset'] = bs.ue();
    sps['frame_crop_bottom_offset'] = bs.ue();
  }
  sps['vui_parameters_present_flag'] = bs.u(1);
  if (sps['vui_parameters_present_flag']) {
    sps['aspect_ratio_info_present_flag'] = bs.u(1);
    if (sps['aspect_ratio_info_present_flag']) {
      sps['aspect_ratio_idc'] = bs.u(8);
      if (sps['aspect_ratio_idc'] == 255) {
        sps['sar_width'] = bs.u(16);
        sps['sar_height'] = bs.u(16);
      }
    }
    sps['overscan_info_present_flag'] = bs.u(1);
    if (sps['overscan_info_present_flag'])
      sps['overscan_appropriate_flag'] = bs.u(1);
    sps['video_signal_type_present_flag'] = bs.u(1);
    if (sps['video_signal_type_present_flag']) {
      sps['video_format'] = bs.u(3);
      sps['video_full_range_flag'] = bs.u(1);
      sps['colour_description_present_flag'] = bs.u(1);
      if (sps['colour_description_present_flag']) {
        sps['colour_primaries'] = bs.u(8);
        sps['transfer_characteristics'] = bs.u(8);
        sps['matrix_coefficients'] = bs.u(8);
      }
    }
    sps['chroma_loc_info_present_flag'] = bs.u(1);
    if (sps['chroma_loc_info_present_flag']) {
      sps['chroma_sample_loc_type_top_field'] = bs.ue();
      sps['chroma_sample_loc_type_bottom_field'] = bs.ue();
    }
    sps['timing_info_present_flag'] = bs.u(1);
    if (sps['timing_info_present_flag']) {
      sps['num_units_in_tick'] = bs.u(32);
      sps['time_scale'] = bs.u(32);
      sps['fixed_frame_rate_flag'] = bs.u(1);
    }
    sps['nal_hrd_parameters_present_flag'] = bs.u(1);
    if (sps['nal_hrd_parameters_present_flag'])
      sps['nal_hrd'] = this.parse_hrd(bs);
    sps['vcl_hrd_parameters_present_flag'] = bs.u(1);
    if (sps['vcl_hrd_parameters_present_flag'])
      sps['vlc_hrd'] = this.parse_hrd(bs);
    if (sps['nal_hrd_parameters_present_flag'] ||
        sps['vcl_hrd_parameters_present_flag'])
      sps['low_delay_hrd_flag'] = bs.u(1);
    sps['pic_struct_present_flag'] = bs.u(1);
    sps['bitstream_restriction_flag'] = bs.u(1);
    if (sps['bitstream_restriction_flag']) {
      sps['motion_vectors_over_pic_boundaries_flag'] = bs.u(1);
      sps['max_bytes_per_pic_denom'] = bs.ue();
      sps['max_bits_per_mb_denom'] = bs.ue();
      sps['log2_max_mv_length_horizontal'] = bs.ue();
      sps['log2_max_mv_length_vertical'] = bs.ue();
      sps['max_num_reorder_frames'] = bs.ue();
      sps['max_dec_frame_buffering'] = bs.ue();
    }
  }
};

bitstream_parser_h264.prototype.parse_hrd = function(bs) {
  var hrd = {};
  hrd['cpb_cnt_minus1'] = bs.ue();
  hrd['bit_rate_scale'] = bs.u(4);
  hrd['cpb_size_scale'] = bs.u(4);
  for (var i = 0; i < hrd['cpb_cnt_minus1'] + 1; i++) {
    hrd['bit_rate_value_minus1[' + i + ']'] = bs.ue();
    hrd['cpb_size_value_minus1[' + i + ']'] = bs.ue();
    hrd['cbr_flag[' + i + ']'] = bs.u(1);
  }
  hrd['initial_cpb_removal_delay_length_minus1'] = bs.u(5);
  hrd['cpb_removal_delay_length_minus1'] = bs.u(5);
  hrd['dpb_output_delay_length_minus1'] = bs.u(5);
  hrd['time_offset_length'] = bs.u(5);
  return hrd;
};

bitstream_parser_h264.prototype.parse_pps = function(bs, pps) {
  pps['pic_parameter_set_id'] = bs.ue();
  pps['seq_parameter_set_id'] = bs.ue();
  pps['entropy_coding_mode_flag'] = bs.u(1);
  pps['bottom_field_pic_order_in_frame_present_flag'] = bs.u(1);
  pps['num_slice_groups_minus1'] = bs.ue();
  pps['num_ref_idx_l0_default_active_minus1'] = bs.ue();
  pps['num_ref_idx_l1_default_active_minus1'] = bs.ue();
  pps['weighted_pred_flag'] = bs.u(1);
  pps['weighted_bipred_idc'] = bs.u(2);
  pps['pic_init_qp_minus26'] = bs.se();
  pps['pic_init_qs_minus26'] = bs.se();
  pps['chroma_qp_index_offset'] = bs.se();
  pps['deblocking_filter_control_present_flag'] = bs.u(1);
  pps['constrained_intra_pred_flag'] = bs.u(1);
  pps['redundant_pic_cnt_present_flag'] = bs.u(1);
  if (more_rbsp_data(bs)) {
    pps['transform_8x8_mode_flag'] = bs.u(1);
    pps['pic_scaling_matrix_present_flag'] = bs.u(1);
    if (pps['pic_scaling_matrix_present_flag']) {
      sps = this.find_nalu(
          [7, 15], 'seq_parameter_set_id', pps['seq_parameter_set_id']);
      nlists = 6;
      if (sps)
        nlists +=
            ('chroma_format_idc' in sps && sps['chroma_format_idc'] == 3) ?
            6 * pps['transform_8x8_mode_flag'] :
            2 * pps['transform_8x8_mode_flag'];
      for (var i = 0; i < nlists; i++) {
        pps['pic_scaling_list_present_flag[' + i + ']'] = bs.u(1);
        if (pps['pic_scaling_list_present_flag[' + i + ']']) {
          var n = i < 6 ? 4 : 8;
          pps['pic_scaling_list_present_flag[' + i + ']'] =
              this.scaling_list(bs, n * n);
        }
      }
    }
  }
};

bitstream_parser_h264.prototype.parse_slice = function(bs, sh) {
  sh['first_mb_in_slice'] = bs.ue();
  sh['slice_type'] = bs.ue();
  sh['pic_parameter_set_id'] = bs.ue();
  var pps =
      this.find_nalu([8], 'pic_parameter_set_id', sh['pic_parameter_set_id']);
  if (pps == null) return sh;

  var sps = this.find_nalu(
      sh['nal_unit_type'] == 20 ? [15] : [7], 'seq_parameter_set_id',
      pps['seq_parameter_set_id']);
  if (sps == null) return sh;

  if ('separate_colour_plane_flag' in sps &&
      sps['separate_colour_plane_flag'] == 1)
    sh['colour_plane_id'] = bs.u(2);

  sh['frame_num'] = bs.u(sps['log2_max_frame_num_minus4'] + 4);

  if (sps['frame_mbs_only_flag'] == 0) {
    sh['field_pic_flag'] = bs.u(1);
    if (sh['field_pic_flag']) sh['bottom_field_flag'] = bs.u(1);
  }

  if (sh['nal_unit_type'] == 5 || ('idr_flag' in sh && sh['idr_flag'] == 1))
    sh['idr_pic_id'] = bs.ue();

  if (sps['pic_order_cnt_type'] == 0) {
    sh['pic_order_cnt_lsb'] =
        bs.u(sps['log2_max_pic_order_cnt_lsb_minus4'] + 4);
    if (pps['bottom_field_pic_order_in_frame_present_flag'] == 1 &&
        (!('field_pic_flag' in sh) || sh['field_pic_flag'] == 0))
      sh['delta_pic_order_cnt_bottom'] = bs.se();
  } else if (
      sps['pic_order_cnt_type'] == 1 &&
      sps['delta_pic_order_always_zero_flag'] == 0) {
    sh['delta_pic_order_cnt[0]'] = bs.se();
    if (pps['bottom_field_pic_order_in_frame_present_flag'] &&
        'field_pic_flag' in sh && sh['field_pic_flag'] == 0)
      sh['delta_pic_order_cnt[1]'] = bs.se();
  }

  if (pps['redundant_pic_cnt_present_flag'] == 1)
    sh['redundant_pic_cnt'] = bs.ue();

  if (!('quality_id' in sh) || sh['quality_id'] == 0) {
    if (sh['slice_type'] % 5 == 1) sh['direct_spatial_mv_pred_flag'] = bs.u(1);

    if (in_range(sh['slice_type'] % 5, [0, 1, 3])) {
      sh['num_ref_idx_active_override_flag'] = bs.u(1);
      if (sh['num_ref_idx_active_override_flag']) {
        sh['num_ref_idx_l0_active_minus1'] = bs.ue();
        if (sh['slice_type'] % 5 == 1)
          sh['num_ref_idx_l1_active_minus1'] = bs.ue();
      }
    }

    if (!in_range(sh['slice_type'] % 5, [2, 4])) {
      for (var list = 0; list < (sh['slice_type'] % 5 == 1 ? 2 : 1); list++) {
        sh['ref_pic_list_modification_flag_l' + list] = bs.u(1);
        if (sh['ref_pic_list_modification_flag_l' + list]) {
          var i = 0;
          var modification_of_pic_nums_idc = 0;
          while (modification_of_pic_nums_idc != 3) {
            modification_of_pic_nums_idc = bs.ue();
            // todo: add command name
            sh['modification_of_pic_nums_idc_l' + list + '[' + i + ']'] =
                modification_of_pic_nums_idc;
            if (in_range(modification_of_pic_nums_idc, [0, 1]))
              sh['abs_diff_pic_num_minus1_l' + list + '[' + i + ']'] = bs.ue();
            else if (modification_of_pic_nums_idc == 2)
              sh['long_term_pic_num_l' + list + '[' + i + ']'] = bs.ue();
            i += 1;
          }
        }
      }
    }

    if ((pps['weighted_pred_flag'] && in_range(sh['slice_type'] % 5, [0, 3])) ||
        (pps['weighted_bipred_idc'] == 1 && sh['slice_type'] % 5 == 1)) {
      sh['luma_log2_weight_denom'] = bs.ue();
      if (!('chroma_format_idc' in sps) || sps['chroma_format_idc'] != 0)
        sh['chroma_log2_weight_denom'] = bs.ue();
      for (var list = 0; list < (sh['slice_type'] % 5 == 1 ? 2 : 1); list++) {
        var num_ref_idx_active_minus1 =
            pps['num_ref_idx_l' + list + '_default_active_minus1'];
        if ('num_ref_idx_l' + list + '_active_minus1' in sh)
          var num_ref_idx_active_minus1 =
              sh['num_ref_idx_l' + list + '_active_minus1'];
        for (var i = 0; i <= num_ref_idx_active_minus1; i++) {
          sh['luma_weight_l' + list + '_flag'] = bs.u(1);
          if (sh['luma_weight_l' + list + '_flag']) {
            sh['luma_weight_l' + list + '[' + i + ']'] = bs.se();
            sh['luma_offset_l' + list + '[' + i + ']'] = bs.se();
          }
          if ('chroma_log2_weight_denom' in sh) {
            sh['chroma_weight_l' + list + '_flag'] = bs.u(1);
            if (sh['chroma_weight_l' + list + '_flag']) {
              for (var j = 0; j < 2; j++) {
                sh['chroma_weight_l' + list + '[' + i + ']' +
                   '[' + j + ']'] = bs.se();
                sh['chroma_offset_l' + list + '[' + i + ']' +
                   '[' + j + ']'] = bs.se();
              }
            }
          }
        }
      }
    }

    if (sh['nal_ref_idc'] != 0) {
      if (sh['nal_unit_type'] == 5 ||
          ('idr_flag' in sh && sh['idr_flag'] == 1)) {
        sh['no_output_of_prior_pics_flag'] = bs.u(1);
        sh['long_term_reference_flag'] = bs.u(1);
      } else {
        sh['adaptive_ref_pic_marking_mode_flag'] = bs.u(1);
        if (sh['adaptive_ref_pic_marking_mode_flag']) {
          var i = 0;
          var memory_management_control_operation = 1;
          while (memory_management_control_operation != 0) {
            memory_management_control_operation = bs.ue();
            sh['memory_management_control_operation[' + i + ']'] =
                memory_management_control_operation;
            if (in_range(memory_management_control_operation, [1, 3]))
              sh['difference_of_pic_nums_minus1[' + i + ']'] = bs.ue();
            if (memory_management_control_operation == 2)
              sh['long_term_pic_num[' + i + ']'] = bs.ue();
            if (in_range(memory_management_control_operation, [3, 6]))
              sh['long_term_frame_idx[' + i + ']'] = bs.ue();
            if (memory_management_control_operation == 4)
              sh['max_long_term_frame_idx_plus1[' + i + ']'] = bs.ue();
            i += 1;
          }
        }
      }

      if ('slice_header_restriction_flag' in sps &&
          sps['slice_header_restriction_flag'] == 0) {
        sh['store_ref_base_pic_flag'] = bs.u(1);
        if (sh['use_ref_base_pic_flag'] ||
            sh['store_ref_base_pic_flag'] && sh['idr_flag'] == 0) {
          sh['adaptive_ref_base_pic_marking_mode_flag'] = bs.u(1);
          if (sh['adaptive_ref_base_pic_marking_mode_flag']) {
            var i = 0;
            var memory_management_base_control_operation = 1;
            while (memory_management_base_control_operation != 0) {
              memory_management_base_control_operation = bs.ue();
              // todo: describe command
              sh['memory_management_base_control_operation[' + i + ']'] =
                  memory_management_control_operation;
              if (memory_management_control_operation == 1)
                sh['difference_of_base_pic_nums_minus1[' + i + ']'] = bs.ue();
              if (memory_management_control_operation == 2)
                sh['long_term_base_pic_num[' + i + ']'] = bs.ue();
              i += 1;
            }
          }
        }
      }
    }
  }

  if (pps['entropy_coding_mode_flag'] &&
      !in_range(sh['slice_type'] % 5, [2, 4]))
    sh['cabac_init_idc'] = bs.ue();

  sh['slice_qp_delta'] = bs.se();
  if (in_range(sh['slice_type'], [3, 4])) {
    if (sh['slice_type'] == 3) sh['sp_for_switch_flag'] = bs.u(1);
    sh['slice_qs_delta'] = bs.se();
  }

  if (pps['deblocking_filter_control_present_flag']) {
    sh['disable_deblocking_filter_idc'] = bs.ue();
    if (sh['disable_deblocking_filter_idc'] != 1) {
      sh['slice_alpha_c0_offset_div2'] = bs.se();
      sh['slice_beta_offset_div2'] = bs.se();
    }
  }

  if (sh['nal_unit_type'] == 20) {
    if (sh['no_inter_layer_pred_flag'] == 0 && sh['quality_id'] == 0) {
      sh['ref_layer_dq_id'] = bs.ue();
      if (sps['inter_layer_deblocking_filter_control_present_flag']) {
        sh['disable_inter_layer_deblocking_filter_idc'] = bs.ue();
        if (sh['disable_inter_layer_deblocking_filter_idc'] != 1) {
          sh['inter_layer_slice_alpha_c0_offset_div2'] = bs.se();
          sh['inter_layer_slice_beta_offset_div2'] = bs.se();
        }
      }
      sh['constrained_intra_resampling_flag'] = bs.u(1);
      if (sps['extended_spatial_scalability_idc'] == 2) {
        if ('chroma_format_idc' in sps && sps['chroma_format_idc'] > 0) {
          sh['ref_layer_chroma_phase_x_plus1_flag'] = bs.u(1);
          sh['ref_layer_chroma_phase_y_plus1'] = bs.u(2);
        }
        sh['scaled_ref_layer_left_offset'] = bs.se();
        sh['scaled_ref_layer_top_offset'] = bs.se();
        sh['scaled_ref_layer_right_offset'] = bs.se();
        sh['scaled_ref_layer_bottom_offset'] = bs.se();
      }
    }

    if (sh['no_inter_layer_pred_flag'] == 0) {
      sh['slice_skip_flag'] = bs.u(1);
      if (sh['slice_skip_flag'])
        sh['num_mbs_in_slice_minus1'] = bs.ue();
      else {
        sh['adaptive_base_mode_flag'] = bs.u(1);
        if (sh['adaptive_base_mode_flag'] == 0)
          sh['default_base_mode_flag'] = bs.u(1);
        sh['adaptive_motion_prediction_flag'] = bs.u(1);
        if (sh['adaptive_motion_prediction_flag'] == 0)
          sh['default_motion_prediction_flag'] = bs.u(1);
        sh['adaptive_residual_prediction_flag'] = bs.u(1);
        if (sh['adaptive_residual_prediction_flag'] == 0)
          sh['default_residual_prediction_flag'] = bs.u(1);
      }
      if ('adaptive_tcoeff_level_prediction_flag' in sps &&
          sps['adaptive_tcoeff_level_prediction_flag'] == 1)
        sh['default_residual_prediction_flag'] = bs.u(1);
    }

    if (sps['slice_header_restriction_flag'] == 0 &&
        (!('slice_skip_flag' in sh) || sh['slice_skip_flag'] == 0)) {
      sh['scan_idx_start'] = bs.u(4);
      sh['scan_idx_end'] = bs.u(4);
    }
  }
};

bitstream_parser_h264.prototype.parse_sei = function(bs, h) {
  var i = 0;
  do {
    var payload_type = 0;
    do {
      payload_type += bs.u(8);
    } while (payload_type != 0 && (payload_type % 255) == 0);

    var payload_size = 0;
    do {
      payload_size += bs.u(8);
    } while (payload_size != 0 && (payload_size % 255) == 0);

    h['payload_type[' + i + ']'] = payload_type;
    h['payload_size[' + i + ']'] = payload_size;

    if (payload_type < this.sei_payload_type.length) {
      h['payload_type[' + i + ']'] += ' ' + this.sei_payload_type[payload_type];
    }

    bs.u(8 * payload_size);
    ++i;
  } while (more_rbsp_data(bs));
};

function bitstream_parser_h265(idoff) {
  bitstream_parser_base.call(this, idoff);
  this.nal_unit_type = [
    'TRAIL_N',
    'TRAIL_R',
    'TSA_N',
    'TSA_R',
    'STSA_N',
    'STSA_R',
    'RADL_N',
    'RADL_R',
    'RASL_N',
    'RASL_R',
    'RSV_VCL_N10',
    'RSV_VCL_N12',
    'RSV_VCL_N14',
    'RSV_VCL_R11',
    'RSV_VCL_R13',
    'RSV_VCL_R15',
    'BLA_W_LP',
    'BLA_W_RADL',
    'BLA_N_LP',
    'IDR_W_RADL',
    'IDR_N_LP',
    'CRA_NUT',
    'RSV_IRAP_VCL22',
    'RSV_IRAP_VCL23',
    'RSV_VCL24',
    'RSV_VCL25',
    'RSV_VCL26',
    'RSV_VCL27',
    'RSV_VCL28',
    'RSV_VCL29',
    'RSV_VCL30',
    'RSV_VCL31',
    'VPS',
    'SPS',
    'PPS',
    'AUD',
    'EOS',
    'EOB',
    'FD_NUT',
    'PREFIX SEI',
    'SUFFIX SEI',
    'RSV_NVCL41',
    'RSV_NVCL47',
    'UNSPEC48',
    'UNSPEC63'
  ];
}

bitstream_parser_h265.prototype = new bitstream_parser_base();
bitstream_parser_h265.prototype.parse = function(buffer, addr) {
  var bs = new bitstream(buffer);
  var h = this.parse_nalu(bs);

  if (h['nal_unit_type'] == 32) {
    this.parse_vps(bs, h);
  } else if (h['nal_unit_type'] == 33) {
    this.parse_sps(bs, h);
    h['@extra'] =
        h['pic_width_in_luma_samples'] + 'x' + h['pic_height_in_luma_samples'];
    h['@extra'] += ' ' + this.profile(h);
    h['@extra'] += ' ' + h['general_level_idc'];
  } else if (h['nal_unit_type'] == 34) {
    this.parse_pps(bs, h);
  } else if ([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 17, 18, 19, 20,
              21].indexOf(h['nal_unit_type']) >= 0) {
    this.slice_segment_header(bs, h);
    h['@keyframe'] = [19, 20].indexOf(h['nal_unit_type']) >= 0 ? 1 : 0;
    if (h['@keyframe'])
      h['@type'] = 'IDR';
    else
      h['@type'] = ['B', 'P', 'I'][h['slice_type']];
    h['@extra'] = this.nal_unit_type[h['nal_unit_type']];
  }

  h['@addr'] = addr;
  if (!('@type' in h)) h['@type'] = this.nal_unit_type[h['nal_unit_type']];
  h['@length'] = buffer.length;
  this.store(h);
};

bitstream_parser_h265.prototype.find_nalu = function(type, key, value) {
  for (var i = this.header.length - 1; i >= 0; i--) {
    if (in_range(this.header[i]['nal_unit_type'], type)) {
      if (key == null)
        return this.header[i];
      else if (this.header[i][key] == value)
        return this.header[i];
    }
  }
  return null;
};

bitstream_parser_h265.prototype.parse_nalu = function(bs) {
  var nalu = {};
  nalu['forbidden_zero_bit'] = bs.u(1);
  nalu['nal_unit_type'] = bs.u(6);
  nalu['nuh_layer_id'] = bs.u(6);
  nalu['nuh_temporal_id_plus1'] = bs.u(3);
  return nalu;
};

bitstream_parser_h265.prototype.profile = function(sps) {
  if (sps['general_profile_idc'] == 1 ||
      sps['general_profile_compatibility_flag[1]'])
    return 'Main';
  if (sps['general_profile_idc'] == 2 ||
      sps['general_profile_compatibility_flag[2]'])
    return 'Main 10';
  if (sps['general_profile_idc'] == 3 ||
      sps['general_profile_compatibility_flag[3]'])
    return 'Main Still Picture';
};

bitstream_parser_h265.prototype.profile_tier_level = function(
    bs, idx, profilePresentFlag, maxNumSubLayersMinus1, h) {
  if (profilePresentFlag) {
    h['general_profile_space' + idx] = bs.u(2);
    h['general_tier_flag' + idx] = bs.u(1);
    h['general_profile_idc' + idx] = bs.u(5);
    h['general_profile_compatibility_flags' + idx] =
        int2str(bs.u(32), 2, 32, '0', 0);
    h['general_progressive_source_flag' + idx] = bs.u(1);
    h['general_interlaced_source_flag' + idx] = bs.u(1);
    h['general_non_packed_constraint_flag' + idx] = bs.u(1);
    h['general_frame_only_constraint_flag' + idx] = bs.u(1);
    if (in_range(h['general_profile_idc' + idx], [4, 5, 6, 7]) ||
        (h['general_profile_compatibility_flags' + idx] & 0xf0)) {
      h['general_max_12bit_constraint_flag' + idx] = bs.u(1);
      h['general_max_10bit_constraint_flag' + idx] = bs.u(1);
      h['general_max_8bit_constraint_flag' + idx] = bs.u(1);
      h['general_max_422chroma_constraint_flag' + idx] = bs.u(1);
      h['general_max_420chroma_constraint_flag' + idx] = bs.u(1);
      h['general_max_monochrome_constraint_flag' + idx] = bs.u(1);
      h['general_intra_constraint_flag' + idx] = bs.u(1);
      h['general_one_picture_only_constraint_flag' + idx] = bs.u(1);
      h['general_lower_bit_rate_constraint_flag' + idx] = bs.u(1);
      h['general_reserved_zero_34bits' + idx] = bs.u(34);
    } else
      h['general_reserved_zero_43bits' + idx] = bs.u(43);
    if ((h['general_profile_idc' + idx] >= 1 &&
         h['general_profile_idc' + idx] <= 5) ||
        (h['general_profile_compatibility_flags' + idx] & 0x3e))
      h['general_inbld_flag' + idx] = bs.u(1);
    else
      h['general_reserved_zero_bit' + idx] = bs.u(1);
  }
  h['general_level_idc' + idx] = bs.u(8);
  for (var i = 0; i < maxNumSubLayersMinus1; i++) {
    h['sub_layer_profile_present_flag' + idx + '[' + i + ']'] = bs.u(1);
    h['sub_layer_level_present_flag' + idx + '[' + i + ']'] = bs.u(1);
  }
  if (maxNumSubLayersMinus1 > 0)
    for (var i = maxNumSubLayersMinus1; i < 8; i++)
      h['reserved_zero_2bits' + idx + '[' + i + ']'] = bs.u(2);
  for (var i = 0; i < maxNumSubLayersMinus1; i++) {
    if (h['sub_layer_profile_present_flag' + idx + '[' + i + ']']) {
      h['sub_layer_profile_space' + idx + '[' + i + ']'] = bs.u(2);
      h['sub_layer_tier_flag' + idx + '[' + i + ']'] = bs.u(1);
      h['sub_layer_profile_idc' + idx + '[' + i + ']'] = bs.u(5);
      h['sub_layer_profile_compatibility_flag' + idx + '[' + i + ']'] =
          bs.u(32);
      h['sub_layer_progressive_source_flag' + idx + '[' + i + ']'] = bs.u(1);
      h['sub_layer_interlaced_source_flag' + idx + '[' + i + ']'] = bs.u(1);
      h['sub_layer_non_packed_constraint_flag' + idx + '[' + i + ']'] = bs.u(1);
      h['sub_layer_frame_only_constraint_flag' + idx + '[' + i + ']'] = bs.u(1);
      if (in_range(
              h['sub_layer_profile_idc' + idx + '[' + i + ']'], [4, 5, 6, 7]) ||
          (h['sub_layer_profile_compatibility_flag' + idx + '[' + i + ']'] &
           0xf0)) {
        h['sub_layer_max_12bit_constraint_flag' + idx + '[' + i + ']'] =
            bs.u(1);
        h['sub_layer_max_10bit_constraint_flag' + idx + '[' + i + ']'] =
            bs.u(1);
        h['sub_layer_max_8bit_constraint_flag' + idx + '[' + i + ']'] = bs.u(1);
        h['sub_layer_max_422chroma_constraint_flag' + idx + '[' + i + ']'] =
            bs.u(1);
        h['sub_layer_max_420chroma_constraint_flag' + idx + '[' + i + ']'] =
            bs.u(1);
        h['sub_layer_max_monochrome_constraint_flag' + idx + '[' + i + ']'] =
            bs.u(1);
        h['sub_layer_intra_constraint_flag' + idx + '[' + i + ']'] = bs.u(1);
        h['sub_layer_one_picture_only_constraint_flag' + idx + '[' + i + ']'] =
            bs.u(1);
        h['sub_layer_lower_bit_rate_constraint_flag' + idx + '[' + i + ']'] =
            bs.u(1);
        h['sub_layer_reserved_zero_34bits' + idx + '[' + i + ']'] = bs.u(34);
      } else
        h['sub_layer_reserved_zero_43bits' + idx + '[' + i + ']'] = bs.u(43);
      if ((h['sub_layer_profile_idc' + idx + '[' + i + ']'] >= 1 &&
           h['sub_layer_profile_idc' + idx + '[' + i + ']'] <= 5) ||
          (h['sub_layer_profile_idc' + idx + '[' + i + ']'] & 0x3e))
        h['sub_layer_inbld_flag' + idx + '[' + i + ']'] = bs.u(1);
      else
        h['sub_layer_reserved_zero_bit' + idx + '[' + i + ']'] = bs.u(1);
    }
    if (h['sub_layer_level_present_flag' + idx + '[' + i + ']'])
      h['sub_layer_level_idc' + idx + '[' + i + ']'] = bs.u(8);
  }
};

bitstream_parser_h265.prototype.hrd_parameters = function(
    bs, idx, commonInfPresentFlag, maxNumSubLayersMinus1, hrd) {
  var suffix = idx == '' ? '' : '[' + idx + ']';
  if (commonInfPresentFlag) {
    hrd['nal_hrd_parameters_present_flag' + suffix] = bs.u(1);
    hrd['vcl_hrd_parameters_present_flag' + suffix] = bs.u(1);
    if (hrd['nal_hrd_parameters_present_flag' + suffix] ||
        hrd['vcl_hrd_parameters_present_flag' + suffix]) {
      hrd['sub_pic_hrd_params_present_flag' + suffix] = bs.u(1);
      if (hrd['sub_pic_hrd_params_present_flag' + suffix]) {
        hrd['tick_divisor_minus2' + suffix] = bs.u(8);
        hrd['du_cpb_removal_delay_increment_length_minus1' + suffix] = bs.u(5);
        hrd['sub_pic_cpb_params_in_pic_timing_sei_flag' + suffix] = bs.u(1);
        hrd['dpb_output_delay_du_length_minus1' + suffix] = bs.u(5);
      }
      hrd['bit_rate_scale' + suffix] = bs.u(4);
      hrd['cpb_size_scale' + suffix] = bs.u(4);
      if (hrd['sub_pic_hrd_params_present_flag' + suffix])
        hrd['cpb_size_du_scale' + suffix] = bs.u(4);
      hrd['initial_cpb_removal_delay_length_minus1' + suffix] = bs.u(5);
      hrd['au_cpb_removal_delay_length_minus1' + suffix] = bs.u(5);
      hrd['dpb_output_delay_length_minus1' + suffix] = bs.u(5);
    }
  }

  for (i = 0; i <= maxNumSubLayersMinus1; i++) {
    hrd['fixed_pic_rate_general_flag' + suffix + '[' + i + ']'] = bs.u(1);
    if (!hrd['fixed_pic_rate_general_flag' + suffix + '[' + i + ']'])
      hrd['fixed_pic_rate_within_cvs_flag' + suffix + '[' + i + ']'] = bs.u(1);
    if (hrd['fixed_pic_rate_within_cvs_flag' + suffix + '[' + i + ']'])
      hrd['elemental_duration_in_tc_minus1' + suffix + '[' + i + ']'] = bs.ue();
    else
      hrd['low_delay_hrd_flag' + suffix + '[' + i + ']'] = bs.u(1);
    if (!hrd['low_delay_hrd_flag' + suffix + '[' + i + ']'])
      hrd['cpb_cnt_minus1' + suffix + '[' + i + ']'] = bs.ue();
    if (hrd['nal_hrd_parameters_present_flag' + suffix]) {
      for (var j = 0; j <= i; j++) {
        hrd['nal_bit_rate_value_minus1' + suffix + '[' + i + '][' + j + ']'] =
            bs.ue();
        hrd['nal_cpb_size_value_minus1' + suffix + '[' + i + '][' + j + ']'] =
            bs.ue();
        if (hrd['nal_sub_pic_hrd_params_present_flag' + suffix]) {
          hrd['nal_cpb_size_du_value_minus1' + suffix + '[' + i + '][' + j +
              ']'] = bs.ue();
          hrd['nal_bit_rate_du_value_minus1' + suffix + '[' + i + '][' + j +
              ']'] = bs.ue();
        }
        hrd['nal_cbr_flag' + suffix + '[' + i + '][' + j + ']'] = bs.u(1);
      }
    }
    if (hrd['vcl_hrd_parameters_present_flag' + suffix]) {
      for (var j = 0; j <= i; j++) {
        hrd['vlc_bit_rate_value_minus1' + suffix + '[' + i + '][' + j + ']'] =
            bs.ue();
        hrd['vlc_cpb_size_value_minus1' + suffix + '[' + i + '][' + j + ']'] =
            bs.ue();
        if (hrd['vlc_sub_pic_hrd_params_present_flag' + suffix]) {
          hrd['vlc_cpb_size_du_value_minus1' + suffix + '[' + i + '][' + j +
              ']'] = bs.ue();
          hrd['vlc_bit_rate_du_value_minus1' + suffix + '[' + i + '][' + j +
              ']'] = bs.ue();
        }
        hrd['vlc_cbr_flag' + suffix + '[' + i + '][' + j + ']'] = bs.u(1);
      }
    }
  }
};

bitstream_parser_h265.prototype.rep_format = function(bs, i, vps) {
  var suffix = '[' + i + ']';
  vps['pic_width_vps_in_luma_samples' + suffix] = bs.u(16);
  vps['pic_height_vps_in_luma_samples' + suffix] = bs.u(16);
  vps['chroma_and_bit_depth_vps_present_flag' + suffix] = bs.u(1);
  if (vps['chroma_and_bit_depth_vps_present_flag' + suffix]) {
    vps['chroma_format_vps_idc' + suffix] = bs.u(2);
    if (vps['chroma_format_vps_idc' + suffix] == 3)
      vps['separate_colour_plane_vps_flag' + suffix] = bs.u(1);
    vps['bit_depth_vps_luma_minus8' + suffix] = bs.u(4);
    vps['bit_depth_vps_chroma_minus8' + suffix] = bs.u(4);
  }
  vps['conformance_window_vps_flag' + suffix] = bs.u(1);
  if (vps['conformance_window_vps_flag' + suffix]) {
    vps['conf_win_vps_left_offset' + suffix] = bs.ue();
    vps['conf_win_vps_right_offset' + suffix] = bs.ue();
    vps['conf_win_vps_top_offset' + suffix] = bs.ue();
    vps['conf_win_vps_bottom_offset' + suffix] = bs.ue();
  }
};

bitstream_parser_h265.prototype.dpb_size = function(bs, i, vps) {
  for (var i = 1; i < vps['#NumOutputLayerSets']; i++) {
    currLsIdx = vps['#OlsIdxToLsIdx[' + i + ']'];
    vps['sub_layer_flag_info_present_flag[' + i + ']'] = bs.u(1);
    for (var j = 0;
         j <= vps['#MaxSubLayersInLayerSetMinus1[' + currLsIdx + ']']; j++) {
      if (j > 0 && vps['sub_layer_flag_info_present_flag[' + i + ']'])
        vps['sub_layer_dpb_info_present_flag[' + i + '][' + j + ']'] = bs.u(1);
      if (vps['sub_layer_dpb_info_present_flag[' + i + '][' + j + ']']) {
        for (k = 0; k < vps['#NumLayersInIdList[' + currLsIdx + ']']; k++)
          if (vps['#NecessaryLayerFlag[' + i + '][' + k + ']'] &&
              (vps['vps_base_layer_internal_flag'] ||
               (vps['#LayerSetLayerIdList[' + currLsIdx + '][' + k + ']'] !=
                0)))
            vps['max_vps_dec_pic_buffering_minus1[' + i + '][' + k + '][' + j +
                ']'] = bs.ue();
        vps['max_vps_num_reorder_pics[' + i + '][' + j + ']'] = bs.ue();
        vps['max_vps_latency_increase_plus1[' + i + '][' + j + ']'] = bs.ue();
      }
    }
  }
};

bitstream_parser_h265.prototype.vps_vui_bsp_hrd_params = function(bs, vps) {
  vps['vps_num_add_hrd_params'] = bs.ue();
  for (var i = vps['vps_num_hrd_parameters'];
       i < vps['vps_num_hrd_parameters'] + vps['vps_num_add_hrd_params']; i++) {
    if (i > 0) vps['cprms_add_present_flag[' + i + ']'] = bs.u(1);
    vps['num_sub_layer_hrd_minus1[' + i + ']'] = bs.ue();
    this.hrd_parameters(
        bs, i, vps['cprms_add_present_flag[' + i + ']'],
        vps['num_sub_layer_hrd_minus1[' + i + ']'], vps);
  }
  if (vps['vps_num_hrd_parameters'] + vps['vps_num_add_hrd_params'] > 0) {
    for (var h = 1; h < vps['#NumOutputLayerSets']; h++) {
      vps['num_signalled_partitioning_schemes[' + h + ']'] = bs.ue();
      for (var j = 1;
           j < vps['num_signalled_partitioning_schemes[' + h + ']'] + 1; j++) {
        vps['num_partitions_in_scheme_minus1[' + h + '][' + j + ']'] = bs.ue();
        for (var k = 0;
             k <= vps['num_partitions_in_scheme_minus1[' + h + '][' + j + ']'];
             k++)
          for (var r = 0; r < vps['#NumLayersInIdList[' +
                                  vps['#OlsIdxToLsIdx[' + h + ']'] + ']'];
               r++)
            vps['layer_included_in_partition_flag[' + h + '][' + j + '][' + k +
                '][' + r + ']'] = bs.u(1);
      }
      for (var i = 0;
           i < vps['num_signalled_partitioning_schemes[' + h + ']'] + 1; i++)
        for (var t = 0; t <= vps['#MaxSubLayersInLayerSetMinus1[' +
                                 vps['#OlsIdxToLsIdx[' + h + ']'] + ']'];
             t++) {
          vps['num_bsp_schedules_minus1[' + h + '][' + i + '][' + t + ']'] =
              bs.ue();
          for (var j = 0; j <=
               vps['num_bsp_schedules_minus1[' + h + '][' + i + '][' + t + ']'];
               j++)
            for (var k = 0; k <=
                 vps['num_partitions_in_scheme_minus1[' + h + '][' + i + ']'];
                 k++) {
              if (vps['vps_num_hrd_parameters'] +
                      vps['vps_num_add_hrd_params'] >
                  1)
                vps['bsp_hrd_idx[' + h + '][' + i + '][' + t + '][' + j + '][' +
                    k + ']'] =
                    bs.u(this.cntbits(
                        vps['vps_num_hrd_parameters'] +
                        vps['vps_num_add_hrd_params']));
              vps['bsp_sched_idx[' + h + '][' + i + '][' + t + '][' + j + '][' +
                  k + ']'] = bs.ue();
            }
        }
    }
  }
};

bitstream_parser_h265.prototype.vps_vui = function(bs, vps) {
  vps['cross_layer_pic_type_aligned_flag'] = bs.u(1);
  if (!vps['cross_layer_pic_type_aligned_flag'])
    vps['cross_layer_irap_aligned_flag'] = bs.u(1);
  if (vps['cross_layer_irap_aligned_flag'])
    vps['all_layers_idr_aligned_flag'] = bs.u(1);
  vps['bit_rate_present_vps_flag'] = bs.u(1);
  vps['pic_rate_present_vps_flag'] = bs.u(1);
  if (vps['bit_rate_present_vps_flag'] || vps['pic_rate_present_vps_flag'])
    for (var i = vps['vps_base_layer_internal_flag'] ? 0 : 1;
         i < vps['#NumLayerSets']; i++)
      for (var j = 0; j <= vps['#MaxSubLayersInLayerSetMinus1[' + i + ']'];
           j++) {
        if (vps['bit_rate_present_vps_flag'])
          vps['bit_rate_present_flag[' + i + '][' + j + ']'] = bs.u(1);
        if (vps['pic_rate_present_vps_flag'])
          vps['pic_rate_present_flag[' + i + '][' + j + ']'] = bs.u(1);
        if (vps['bit_rate_present_flag[' + i + '][' + j + ']']) {
          vps['avg_bit_rate[' + i + '][' + j + ']'] = bs.u(16);
          vps['max_bit_rate[' + i + '][' + j + ']'] = bs.u(16);
        }
        if (vps['pic_rate_present_flag[' + i + '][' + j + ']']) {
          vps['constant_pic_rate_idc[' + i + '][' + j + ']'] = bs.u(2);
          vps['avg_pic_rate[' + i + '][' + j + ']'] = bs.u(16);
        }
      }
  vps['video_signal_info_idx_present_flag'] = bs.u(1);
  if (vps['video_signal_info_idx_present_flag'])
    vps['vps_num_video_signal_info_minus1'] = bs.u(4);
  for (var i = 0; i <= vps['vps_num_video_signal_info_minus1']; i++) {
    vps['video_vps_format[' + i + ']'] = bs.u(3);
    vps['video_full_range_vps_flag[' + i + ']'] = bs.u(1);
    vps['colour_primaries_vps[' + i + ']'] = bs.u(8);
    vps['transfer_characteristics_vps[' + i + ']'] = bs.u(8);
    vps['matrix_coeffs_vps[' + i + ']'] = bs.u(8);
  }
  if (vps['video_signal_info_idx_present_flag'] &&
      vps['vps_num_video_signal_info_minus1'] > 0)
    for (var i = vps['vps_base_layer_internal_flag'] ? 0 : 1;
         i <= vps['vps_max_layers_minus1']; i++)
      vps['vps_video_signal_info_idx[' + i + ']'] = bs.u(4);
  vps['tiles_not_in_use_flag'] = bs.u(1);
  if (!vps['tiles_not_in_use_flag']) {
    for (var i = vps['vps_base_layer_internal_flag'] ? 0 : 1;
         i <= vps['vps_max_layers_minus1']; i++) {
      vps['tiles_in_use_flag[' + i + ']'] = bs.u(1);
      if (vps['tiles_in_use_flag[' + i + ']'])
        vps['loop_filter_not_across_tiles_flag[' + i + ']'] = bs.u(1);
    }
    for (var i = vps['vps_base_layer_internal_flag'] ? 1 : 2;
         i <= vps['vps_max_layers_minus1']; i++)
      for (var j = 0; j < vps['#NumDirectRefLayers[' +
                              vps['layer_id_in_nuh[' + i + ']'] + ']'];
           j++) {
        var layerIdx =
            vps['#LayerIdxInVps[' +
                vps['#IdDirectRefLayer[' + vps['layer_id_in_nuh[' + i + ']']] +
                '][' + j + ']'];
        if (vps['tiles_in_use_flag[' + i + ']'] &&
            vps['tiles_in_use_flag[' + layerIdx + ']'])
          vps['tile_boundaries_aligned_flag[' + i + '][' + j + ']'] = bs.u(1);
      }
  }
  vps['wpp_not_in_use_flag'] = bs.u(1);
  if (!vps['wpp_not_in_use_flag'])
    for (var i = vps['vps_base_layer_internal_flag'] ? 0 : 1;
         i <= vps['vps_max_layers_minus1']; i++)
      vps['wpp_in_use_flag[' + i + ']'] = bs.u(1);
  vps['single_layer_for_non_irap_flag'] = bs.u(1);
  vps['higher_layer_irap_skip_flag'] = bs.u(1);
  vps['ilp_restricted_ref_layers_flag'] = bs.u(1);
  if (vps['ilp_restricted_ref_layers_flag'])
    for (var i = 1; i <= vps['vps_max_layers_minus1']; i++)
      for (var j = 0; j < vps['#NumDirectRefLayers[' +
                              vps['layer_id_in_nuh[' + i + ']'] + ']'];
           j++)
        if (vps['vps_base_layer_internal_flag'] ||
            vps['#IdDirectRefLayer[' + vps['layer_id_in_nuh[' + i + ']'] +
                '][' + j + ']'] > 0) {
          vps['min_spatial_segment_offset_plus1[' + i + '][' + j + ']'] =
              bs.ue();
          if (vps['min_spatial_segment_offset_plus1[' + i + '][' + j + ']'] >
              0) {
            vps['ctu_based_offset_enabled_flag[' + i + '][' + j + ']'] =
                bs.u(1);
            if (vps['ctu_based_offset_enabled_flag[' + i + '][' + j + ']'])
              vps['min_horizontal_ctu_offset_plus1[' + i + '][' + j + ']'] =
                  bs.ue();
          }
        }
  vps['vps_vui_bsp_hrd_present_flag'] = bs.u(1);
  if (vps['vps_vui_bsp_hrd_present_flag']) this.vps_vui_bsp_hrd_params(bs, vps);
  for (var i = 1; i <= vps['vps_max_layers_minus1']; i++)
    if (vps['#NumDirectRefLayers[' + vps['layer_id_in_nuh[' + i + ']'] + ']'] ==
        0)
      vps['base_layer_parameter_set_compatibility_flag[' + i + ']'] = bs.u(1);
};

bitstream_parser_h265.prototype.vps_extension = function(bs, vps) {
  if (vps['vps_max_layers_minus1'] > 0 && vps['vps_base_layer_internal_flag'])
    this.profile_tier_level(bs, 1, 0, vps['vps_max_sub_layers_minus1'], vps)
    vps['splitting_flag'] = bs.u(1);
  var NumScalabilityTypes = 0;
  for (var i = 0; i < 16; i++) {
    vps['scalability_mask_flag[' + i + ']'] = bs.u(1)
    NumScalabilityTypes += vps['scalability_mask_flag[' + i + ']'];
  }
  for (var j = 0; j < (NumScalabilityTypes - vps['splitting_flag']); j++)
    vps['dimension_id_len_minus1[' + j + ']'] = bs.u(3);
  vps['vps_nuh_layer_id_present_flag'] = bs.u(1);
  for (var i = 1; i <= vps['vps_max_layers_minus1']; i++) {
    if (vps['vps_nuh_layer_id_present_flag'])
      vps['layer_id_in_nuh[' + i + ']'] = bs.u(6);
    if (!vps['splitting_flag'])
      for (var j = 0; j < NumScalabilityTypes; j++)
        vps['dimension_id[' + i + '][' + j + ']'] =
            bs.u(vps['dimension_id_len_minus1[' + j + ']'] + 1);
  }
  vps['#NumViews'] = 1;
  for (var i = 0; i <= vps['vps_max_layers_minus1']; i++) {
    var lId = vps['layer_id_in_nuh[' + i + ']'];
    for (var smIdx = 0, j = 0; smIdx < 16; smIdx++) {
      if (vps['scalability_mask_flag[' + smIdx + ']']) {
        vps['#ScalabilityId[' + i + '][' + smIdx + ']'] =
            vps['dimension_id[' + i + '][' + j + ']'];
        j++;
      } else
        vps['#ScalabilityId[' + i + '][' + smIdx + ']'] = 0;
    }
    vps['#DepthLayerFlag[' + lId + ']'] =
        vps['#ScalabilityId[' + i + '][' + 0 + ']'];
    vps['#ViewOrderIdx[' + lId + ']'] =
        vps['#ScalabilityId[' + i + '][' + 1 + ']'];
    vps['#DependencyId[' + lId + ']'] =
        vps['#ScalabilityId[' + i + '][' + 2 + ']'];
    vps['#AuxId[' + lId + ']'] = vps['#ScalabilityId[' + i + '][' + 3 + ']'];
    if (i > 0) {
      var newViewFlag = 1;
      for (var j = 0; j < i; j++)
        if (vps['#ViewOrderIdx[' + lId + ']'] ==
            vps['#ViewOrderIdx[' + vps['layer_id_in_nuh[' + j + ']'] + ']'])
          newViewFlag = 0;
      vps['#NumViews'] += newViewFlag;
    }
  }
  vps['view_id_len'] = bs.u(4);
  if (vps['view_id_len'] > 0)
    for (var i = 0; i < NumViews; i++)
      vps['view_id_val[' + i + ']'] = bs.u(vps['view_id_len']);
  var NumDirectRefLayers = new Uint8Array(63);
  for (var i = 1; i <= vps['vps_max_layers_minus1']; i++)
    NumDirectRefLayers[i] = 0;
  for (var j = 0; j < i; j++)
    vps['direct_dependency_flag[' + i + '][' + j + ']'] = bs.u(1);
  NumDirectRefLayers[j] += vps['direct_dependency_flag[' + i + '][' + j + ']'];

  for (i = 0; i <= vps['vps_max_layers_minus1']; i++)
    for (j = 0; j <= vps['vps_max_layers_minus1']; j++) {
      vps['#DependencyFlag[' + i + '][' + j + ']'] =
          vps['direct_dependency_flag[' + i + '][' + j + ']'];
      for (k = 0; k < i; k++)
        if (vps['direct_dependency_flag[' + i + '][' + k + ']'] &&
            vps['#DependencyFlag[' + k + '][' + j + ']'])
          vps['#DependencyFlag[' + i + '][' + j + ']'] = 1;
    }

  for (i = 0; i <= vps['vps_max_layers_minus1']; i++) {
    var iNuhLId = vps['layer_id_in_nuh[' + i + ']'];
    var d = 0, r = 0, p = 0;
    for (var j = 0; j <= vps['vps_max_layers_minus1']; j++) {
      var jNuhLid = vps['layer_id_in_nuh[' + j + ']'];
      if (vps['direct_dependency_flag[' + i + '][' + j + ']'])
        vps['#IdDirectRefLayer[' + iNuhLId + '][' + d + ']'] = jNuhLid;
      d++;
      if (vps['#DependencyFlag[' + i + '][' + j + ']'])
        vps['#IdRefLayer[' + iNuhLId + '][' + r + ']'] = jNuhLid;
      r++;
      if (vps['#DependencyFlag[' + j + '][' + i + ']'])
        vps['#IdPredictedLayerr[' + iNuhLId + '][' + p + ']'] = jNuhLid;
      p++;
    }
    vps['#NumDirectRefLayers[' + iNuhLId + ']'] = d;
    vps['#NumRefLayers[' + iNuhLId + ']'] = r;
    vps['#NumPredictedLayers[' + iNuhLId + ']'] = p;
    vps['#LayerIdxInVps[' + iNuhLId + ']'] = i;
  }

  for (var i = 0; i <= 63; i++) vps['#layerIdInListFlag[' + i + ']'] = 0;
  var k = 0;
  for (var i = 0; i <= vps['vps_max_layers_minus1']; i++) {
    var iNuhLId = vps['layer_id_in_nuh[' + i + ']'];
    if (vps['#NumDirectRefLayers[' + iNuhLId + ']'] == 0) {
      vps['#TreePartitionLayerIdList[' + k + '][' + 0 + ']'] = iNuhLId;
      for (var j = 0, h = 1; j < vps['#NumPredictedLayers[' + iNuhLId + ']'];
           j++) {
        var predLId = vps['#IdPredictedLayer[' + iNuhLId + '][' + j + ']'];
        if (!vps['#layerIdInListFlag[' + predLId + ']']) {
          vps['#TreePartitionLayerIdList[' + k + '][' + h + ']'] = predLId;
          h++;
          vps['#layerIdInListFlag[' + predLId + ']'] = 1
        }
      }
      vps['#NumLayersInTreePartition[' + k + ']'] = h;
      k++;
    }
  }
  vps['#NumIndependentLayers'] = k;
  if (vps['#NumIndependentLayers'] > 1) vps['num_add_layer_sets'] = bs.ue();
  vps['#NumLayerSets'] =
      vps['vps_num_layer_sets_minus1'] + 1 + (vps['num_add_layer_sets'] || 0);
  var nuhLayerIdA = 0;
  for (var i = 0; i < (vps['num_add_layer_sets'] || 0); i++) {
    for (var j = 1; j < vps['#NumIndependentLayers']; j++)
      vps['highest_layer_idx_plus1[' + i + '][' + j + ']'] =
          bs.u(this.cntbits(vps['#NumLayersInTreePartition[' + j + ']'] + 1));
    var layerNum = 0;
    var lsIdx = vps['vps_num_layer_sets_minus1'] + 1 + i;
    for (var treeIdx = 1; treeIdx < vps['#NumIndependentLayers']; treeIdx++)
      for (var layerCnt = 0; layerCnt <
           vps['highest_layer_idx_plus1[' + i + '][' + treeIdx + ']'];
           layerCnt++) {
        vps['#LayerSetLayerIdList[' + lsIdx + '][' + layerNum + ']'] =
            vps['#TreePartitionLayerIdList[' + treeIdx + '][' + layerCnt + ']'];
        layerNum++;
        if (vps['#LayerSetLayerIdList[' + lsIdx + '][' + layerNum + ']'] >
            nuhLayerIdA)
          nuhLayerIdA =
              vps['#LayerSetLayerIdList[' + lsIdx + '][' + layerNum + ']'];
      }
    vps['#NumLayersInIdList[' + lsIdx + ']'] = layerNum;
  }

  vps['vps_sub_layers_max_minus1_present_flag'] = bs.u(1);
  if (vps['vps_sub_layers_max_minus1_present_flag'])
    for (var i = 0; i <= vps['vps_max_layers_minus1']; i++)
      vps['sub_layers_vps_max_minus1[' + i + ']'] = bs.u(3);
  vps['max_tid_ref_present_flag'] = bs.u(1);
  if (vps['max_tid_ref_present_flag'])
    for (var i = 0; i < vps['vps_max_layers_minus1']; i++)
      for (var j = i + 1; j <= vps['vps_max_layers_minus1']; j++)
        if (vps['direct_dependency_flag[' + j + '][' + i + ']'])
          vps['max_tid_il_ref_pics_plus1[' + i + '][' + j + ']'] = bs.u(3);
  vps['default_ref_layers_active_flag'] = bs.u(1);
  vps['vps_num_profile_tier_level_minus1'] = bs.ue();
  for (var i = vps['vps_base_layer_internal_flag'] ? 2 : 1;
       i <= vps['vps_num_profile_tier_level_minus1']; i++) {
    vps['vps_profile_present_flag[' + i + ']'] = bs.u(1);
    this.profile_tier_level(
        bs, i, vps['vps_profile_present_flag[' + i + ']'],
        vps['vps_max_sub_layers_minus1'], vps);
  }

  if (vps['#NumLayerSets'] > 1) {
    vps['num_add_olss'] = bs.ue();
    vps['default_output_layer_idc'] = bs.u(2);
  }

  for (var i = 0; i < vps['#NumLayerSets']; i++) {
    var maxSlMinus1 = 0;
    for (k = 0; k < NumLayersInIdList[i]; k++) {
      lId = vps['#LayerSetLayerIdList[' + i + '][' + k + ']'];
      maxSlMinus1 = Math.max(
          maxSLMinus1,
          vps['sub_layers_vps_max_minus1[' +
              vps['#LayerIdxInVps[' + lId + ']'] + ']']);
    }
    vps['#MaxSubLayersInLayerSetMinus1[' + i + ']'] = maxSlMinus1;
  }

  vps['#NumOutputLayerSets'] =
      (vps['num_add_olss'] || 0) + vps['#NumLayerSets'];
  for (var i = 1; i < vps['#NumOutputLayerSets']; i++) {
    if (vps['#NumLayerSets'] > 2 && i >= vps['#NumLayerSets'])
      vps['layer_set_idx_for_ols_minus1[' + i + ']'] =
          bs.u(this.cntbits(vps['#NumLayerSets'] - 1));
    var OlsIdxToLsIdx = vps['#OlsIdxToLsIdx[' + i + ']'] =
        i < vps['#NumLayerSets'] ?
        i :
        ((vps['layer_set_idx_for_ols_minus1[' + i + ']'] || 0) + 1);
    if (i > vps['vps_num_layer_sets_minus1'] ||
        (vps['default_output_layer_idc'] || 0) == 2)
      for (var j = 0; j < vps['#NumLayersInIdList[' + OlsIdxToLsIdx + ']']; j++)
        vps['#OutputLayerFlag[' + i + '][' + j + ']'] =
            vps['output_layer_flag[' + i + '][' + j + ']'] = bs.u(1);
    else
      for (var j = 0; j < vps['#NumLayersInIdList[' + OlsIdxToLsIdx + ']'];
           j++) {
        var defaultOutputLayerIdc = (vps['default_output_layer_idc'] || 0);
        if (defaultOutputLayerIdc == 0 ||
            (defaultOutputLayerIdc == 1 &&
             vps['#LayerSetLayerIdList[' + OlsIdxToLsIdx + '][' + j + ']'] ==
                 nuhLayerIdA))
          vps['#OutputLayerFlag[' + i + '][' + j + ']'] = 1;
      }
    vps['#NumOutputLayersInOutputLayerSet[' + i + ']'] = 0;
    for (var j = 0; j < vps['#NumLayersInIdList[' + OlsIdxToLsIdx + ']']; j++) {
      vps['#NumOutputLayersInOutputLayerSet[' + i + ']'] +=
          vps['#OutputLayerFlag[' + i + '][' + j + ']'];
      if (vps['#OutputLayerFlag[' + i + '][' + j + ']'])
        vps['#OlsHighestOutputLayerId[' + i + ']'] =
            vps['#LayerSetLayerIdList[' + OlsIdxToLsIdx + '][' + j + ']'];
    }
    for (var j = 0; j < vps['#NumLayersInIdList[' + OlsIdxToLsIdx + ']']; j++) {
      vps['#NecessaryLayerFlag[' + i + '][' + j + ']'] =
          vps['#OutputLayerFlag[' + i + '][' + j + ']'];
      var currLayerId =
          vps['#LayerSetLayerIdList[' + j + '][' + rLsLayerIdx + ']'];
      for (var rLsLayerIdx = 0; rLsLayerIdx < j; rLsLayerIdx++) {
        var refLayerId =
            vps['#LayerSetLayerIdList[' + j + '][' + rLsLayerIdx + ']'];
        if (vps['#DependencyFlag[' +
                vps['#LayerIdxInVps[' + currLayerId + ']'] + '][' +
                vps['#LayerIdxInVps[' + refLayerId + ']'] + ']'])
          vps['#NecessaryLayerFlag[' + i + '][' + j + ']'] = 1;
      }
    }
    for (var j = 0; j < vps['#NumLayersInIdList[' + OlsIdxToLsIdx + ']']; j++) {
      if (vps['#NecessaryLayerFlag[' + i + '][' + j + ']'] &&
          vps['vps_num_profile_tier_level_minus1'] > 0)
        vps['profile_tier_level_idx[' + i + '][' + j + ']'] =
            bs.u(this.cntbits(vps['vps_num_profile_tier_level_minus1'] + 1));
    }
    if (vps['#NumOutputLayersInOutputLayerSet[' + i + ']'] == 1 &&
        vps['#NumDirectRefLayers[' +
            vps['#OlsHighestOutputLayerId[' + i + ']'] + ']'] > 0)
      vps['alt_output_layer_flag[' + i + ']'] = bs.u(1);
  }
  vps['vps_num_rep_formats_minus1'] = bs.ue();
  for (var i = 0; i <= vps['vps_num_rep_formats_minus1']; i++)
    this.rep_format(bs, i, vps);
  if (vps['vps_num_rep_formats_minus1'] > 0)
    vps['rep_format_idx_present_flag'] = bs.u(1);
  if (vps['rep_format_idx_present_flag']) {
    var nbits = this.cntbits(vps['vps_num_rep_formats_minus1'] + 1);
    for (var i = vps['vps_base_layer_internal_flag'] ? 1 : 0;
         i <= vps['vps_max_layers_minus1']; i++)
      vps['vps_rep_format_idx[' + i + ']'] = bs.u(nbits);
  }
  vps['max_one_active_ref_layer_flag'] = bs.u(1);
  vps['vps_poc_lsb_aligned_flag'] = bs.u(1);
  for (var i = 1; i <= vps['vps_max_layers_minus1']; i++)
    if (vps['#NumDirectRefLayers[' + (vps['layer_id_in_nuh[' + i + ']'] || 0) +
            ']'] == 0)
      vps['poc_lsb_not_present_flag[' + i + ']'] = bs.u(1);
  this.dpb_size(bs, vps);
  vps['direct_dep_type_len_minus2'] = bs.ue();
  vps['direct_dependency_all_layers_flag'] = bs.u(1);
  if (vps['direct_dependency_all_layers_flag'])
    vps['direct_dependency_all_layers_type'] =
        bs.u(vps['direct_dep_type_len_minus2'] + 2);
  else {
    for (var i = vvps['ps_base_layer_internal_flag'] ? 1 : 2;
         i <= vps['vps_max_layers_minus1']; i++)
      for (var j = vps['vps_base_layer_internal_flag'] ? 0 : 1; j < i; j++)
        if (vps['direct_dependency_flag[' + i + '][' + j + ']'])
          vps['direct_dependency_type[' + i + '][' + j + ']'] =
              bs.u(vps['direct_dep_type_len_minus2'] + 2);
  }
  vps['vps_non_vui_extension_length'] = bs.ue();
  for (var i = 1; i <= vps['vps_non_vui_extension_length']; i++)
    vps['vps_non_vui_extension_data_byte'] = bs.u(8);
  vps['vps_vui_present_flag'] = bs.u(1);
  if (vps['vps_vui_present_flag']) {
    while (!bs.bytealign()) bs.u(1);
    this.vps_vui(bs, vps);
  }
};

bitstream_parser_h265.prototype.vps_3d_extension = function(bs, vps) {
  vps['cp_precision'] = bs.ue();
  for (var n = 1; n < vps['#NumViews']; n++) {
    i = vps['#ViewOIdxList[' + n + ']'];
    vps['num_cp[' + i + ']'] = bs.u(6);
    if (vps['num_cp[' + i + ']'] > 0) {
      vps['cp_in_slice_segment_header_flag[' + i + ']'] = bs.u(1);
      for (var m = 0; m < vps['num_cp[' + i + ']']; m++) {
        vps['cp_ref_voi[' + i + '][' + m + ']'] = bs.ue();
        if (!vps['cp_in_slice_segment_header_flag[' + i + ']']) {
          var j = vps['cp_ref_voi[' + i + '][' + m + ']'];
          vps['vps_cp_scale[' + i + '][' + j + ']'] = bs.se();
          vps['vps_cp_off[' + i + '][' + j + ']'] = bs.se();
          vps['vps_cp_inv_scale_plus_scale[' + i + '][' + j + ']'] = bs.se();
          vps['vps_cp_inv_off_plus_off[' + i + '][' + j + ']'] = bs.se();
        }
      }
    }
  }
};

bitstream_parser_h265.prototype.parse_vps = function(bs, vps) {
  vps['vps_video_parameter_set_id'] = bs.u(4);
  vps['vps_base_layer_internal_flag'] = bs.u(1);
  vps['vps_base_layer_available_flag '] = bs.u(1);
  vps['vps_max_layers_minus1'] = bs.u(6);
  vps['vps_max_sub_layers_minus1'] = bs.u(3);
  vps['vps_temporal_id_nesting_flag'] = bs.u(1);
  vps['vps_reserved_0xffff_16bits'] = bs.u(16);
  this.profile_tier_level(bs, '', 1, vps['vps_max_sub_layers_minus1'], vps);
  vps['vps_sub_layer_ordering_info_present_flag'] = bs.u(1);
  for (var i =
           (vps['vps_sub_layer_ordering_info_present_flag'] ?
                0 :
                vps['vps_max_sub_layers_minus1']);
       i <= vps['vps_max_sub_layers_minus1']; i++) {
    vps['vps_max_dec_pic_buffering_minus1[' + i + ']'] = bs.ue();
    vps['vps_max_num_reorder_pics[' + i + ']'] = bs.ue();
    vps['vps_max_latency_increase_plus1[' + i + ']'] = bs.ue();
  }
  vps['vps_max_layer_id'] = bs.u(6);
  vps['vps_num_layer_sets_minus1'] = bs.ue();
  for (var i = 1; i <= vps['vps_num_layer_sets_minus1']; i++)
    for (var j = 0; j <= vps['vps_max_layer_id']; j++)
      vps['layer_id_included_flag[' + i + '][' + j + ']'] = bs.u(1);
  vps['vps_timing_info_present_flag'] = bs.u(1);
  if (vps['vps_timing_info_present_flag']) {
    vps['vps_num_units_in_tick'] = bs.u(32);
    vps['vps_time_scale'] = bs.u(32);
    vps['vps_poc_proportional_to_timing_flag'] = bs.u(1);
    if (vps['vps_poc_proportional_to_timing_flag'])
      vps['vps_num_ticks_poc_diff_one_minus1'] = bs.ue();
    vps['vps_num_hrd_parameters'] = bs.ue();
    for (var i = 0; i < vps['vps_num_hrd_parameters']; i++) {
      vps['hrd_layer_set_idx[' + i + ']'] = bs.ue();
      if (i > 0) vps['cprms_present_flag[' + i + ']'] = bs.u(1);
      this.hrd_parameters(
          bs, i, i == 0 || vps['cprms_present_flag[' + i + ']'],
          vps['vps_max_sub_layers_minus1'], vps);
    }
  }

  vps['vps_extension_flag'] = bs.u(1);
  if (vps['vps_extension_flag']) {
    while (!bs.bytealign()) bs.u(1);
    this.vps_extension(bs, vps);
    vps['vps_extension2_flag'] = bs.u(1);
    if (vps['vps_extension2_flag']) {
      vps['vps_3d_extension_flag'] = bs.u(1);
      if (vps['vps_3d_extension_flag']) {
        while (!bs.bytealign()) bs.u(1);
        this.vps_3d_extension(bs, vui);
      }
      vps['vps_extension3_flag'] = bs.u(1);
      if (vps['vps_extension3_flag'])
        for (var i = 0; more_rbsp_data(bs); i++)
          vps['vps_extension_data_flag[' + i + ']'] = bs.u(1);
    }
  }
  return vps;
};

bitstream_parser_h265.prototype.short_term_ref_pic_set = function(
    bs, stRpsIdx, num_short_term_ref_pic_sets, rps, sps) {
  var idx = stRpsIdx == num_short_term_ref_pic_sets ? '' : '[' + stRpsIdx + ']';
  if (stRpsIdx > 0) rps['inter_ref_pic_set_prediction_flag' + idx] = bs.u(1);
  if (rps['inter_ref_pic_set_prediction_flag' + idx]) {
    if (stRpsIdx == num_short_term_ref_pic_sets)
      rps['delta_idx_minus1' + idx] = bs.ue();
    rps['delta_rps_sign' + idx] = bs.u(1);
    rps['abs_delta_rps_minus1' + idx] = bs.ue();
    var RefRpsIdx = stRpsIdx - 1 -
        (stRpsIdx == num_short_term_ref_pic_sets ?
             rps['delta_idx_minus1' + idx] :
             0);
    var deltaRps = (1 - 2 * rps['delta_rps_sign' + idx]) *
        (rps['abs_delta_rps_minus1' + idx] + 1);
    var RefNumDeltaPocs = sps['#NumDeltaPocs[' + RefRpsIdx + ']'];
    var NumDeltaPocs = 0;
    for (var j = 0; j <= RefNumDeltaPocs; j++) {
      rps['used_by_curr_pic_flag' + idx + '[' + j + ']'] = bs.u(1);
      if (rps['used_by_curr_pic_flag' + idx + '[' + j + ']'] == 0)
        rps['use_delta_flag' + idx + '[' + j + ']'] = bs.u(1);
      if (rps['used_by_curr_pic_flag' + idx + '[' + j + ']'] ||
          rps['use_delta_flag' + idx + '[' + j + ']'])
        NumDeltaPocs++;
    }
    rps['#NumDeltaPocs' + idx] = NumDeltaPocs;
  } else {
    rps['num_negative_pics' + idx] = bs.ue();
    rps['num_positive_pics' + idx] = bs.ue();
    for (var j = 0; j < rps['num_negative_pics' + idx]; j++) {
      rps['delta_poc_s0_minus1' + idx + '[' + j + ']'] = bs.ue();
      rps['used_by_curr_pic_s0_flag' + idx + '[' + j + ']'] = bs.u(1);
    }
    for (var j = 0; j < rps['num_positive_pics' + idx]; j++) {
      rps['delta_poc_s1_minus1' + idx + '[' + j + ']'] = bs.ue();
      rps['used_by_curr_pic_s1_flag' + idx + '[' + j + ']'] = bs.u(1);
    }
    rps['#NumDeltaPocs' + idx] =
        rps['num_negative_pics' + idx] + rps['num_positive_pics' + idx];
  }
};

bitstream_parser_h265.prototype.scaling_list_data = function(bs, list) {
  for (var sizeId = 0; sizeId < 4; sizeId++) {
    for (var matrixId = 0; matrixId < ((sizeId == 3) ? 2 : 6); matrixId++) {
      list['scaling_list_pred_mode_flag[' + sizeId + '][' + matrixId + ']'] =
          bs.u(1);
      if (!list
              ['scaling_list_pred_mode_flag[' + sizeId + '][' + matrixId + ']'])
        list
            ['scaling_list_pred_matrix_id_delta[' + sizeId + '][' + matrixId +
             ']'] = bs.ue();
      else {
        var nextCoef = 8;
        var coefNum = Math.min(64, (1 << (4 + (sizeId << 1))));
        if (sizeId > 1) {
          var scaling_list_dc_coef_minus8 = bs.se();
          nextCoef = scaling_list_dc_coef_minus8 + 8;
        }
        var rowLen = Math.sqrt(coefNum);
        var scalingList = new Array(coefNum);
        for (var i = 0; i < coefNum; i++) {
          var scaling_list_delta_coef = bs.se();
          nextCoef = (nextCoef + scaling_list_delta_coef + 256) % 256;
          scalingList[i] = nextCoef;
        }
        list['scaling_list_pred_mode_flag[' + sizeId + '][' + matrixId + ']'] =
            scalingList;
      }
    }
  }
};

bitstream_parser_h265.prototype.parse_sps = function(bs, sps) {
  sps['sps_video_parameter_set_id'] = bs.u(4);
  sps['sps_max_sub_layers_minus1'] = bs.u(3);
  sps['sps_temporal_id_nesting_flag'] = bs.u(1);
  this.profile_tier_level(bs, '', 1, sps['sps_max_sub_layers_minus1'], sps);
  sps['sps_seq_parameter_set_id'] = bs.ue();
  sps['chroma_format_idc'] = bs.ue();
  if (sps['chroma_format_idc'] == 3)
    sps['separate_colour_plane_flag'] = bs.u(1);

  sps['pic_width_in_luma_samples'] = bs.ue();
  sps['pic_height_in_luma_samples'] = bs.ue();
  sps['conformance_window_flag'] = bs.u(1);
  if (sps['conformance_window_flag']) {
    sps['conf_win_left_offset'] = bs.ue();
    sps['conf_win_right_offset'] = bs.ue();
    sps['conf_win_top_offset'] = bs.ue();
    sps['conf_win_bottom_offset'] = bs.ue();
  }
  sps['bit_depth_luma_minus8'] = bs.ue();
  sps['bit_depth_chroma_minus8'] = bs.ue();
  sps['log2_max_pic_order_cnt_lsb_minus4'] = bs.ue();
  sps['sps_sub_layer_ordering_info_present_flag'] = bs.u(1);
  for (var i =
           (sps['sps_sub_layer_ordering_info_present_flag'] ?
                0 :
                sps['sps_max_sub_layers_minus1']);
       i <= sps['sps_max_sub_layers_minus1']; i++) {
    sps['sps_max_dec_pic_buffering_minus1[' + i + ']'] = bs.ue();
    sps['sps_max_num_reorder_pics[' + i + ']'] = bs.ue();
    sps['sps_max_latency_increase_plus1[' + i + ']'] = bs.ue();
  }
  sps['log2_min_luma_coding_block_size_minus3'] = bs.ue();
  sps['log2_diff_max_min_luma_coding_block_size'] = bs.ue();
  sps['log2_min_transform_block_size_minus2'] = bs.ue();
  sps['log2_diff_max_min_transform_block_size'] = bs.ue();
  sps['max_transform_hierarchy_depth_inter'] = bs.ue();
  sps['max_transform_hierarchy_depth_intra'] = bs.ue();
  sps['scaling_list_enabled_flag'] = bs.u(1);
  if (sps['scaling_list_enabled_flag']) {
    sps['sps_scaling_list_data_present_flag'] = bs.u(1);
    if (sps['sps_scaling_list_data_present_flag'])
      this.scaling_list_data(bs, sps);
  }
  sps['amp_enabled_flag'] = bs.u(1);
  sps['sample_adaptive_offset_enabled_flag'] = bs.u(1);
  sps['pcm_enabled_flag'] = bs.u(1);
  if (sps['pcm_enabled_flag']) {
    sps['pcm_sample_bit_depth_luma_minus1'] = bs.u(4);
    sps['pcm_sample_bit_depth_chroma_minus1'] = bs.u(4);
    sps['log2_min_pcm_luma_coding_block_size_minus3'] = bs.ue();
    sps['log2_diff_max_min_pcm_luma_coding_block_size'] = bs.ue();
    sps['pcm_loop_filter_disabled_flag'] = bs.u(1);
  }
  sps['num_short_term_ref_pic_sets'] = bs.ue();
  for (var i = 0; i < sps['num_short_term_ref_pic_sets']; i++)
    this.short_term_ref_pic_set(
        bs, i, sps['num_short_term_ref_pic_sets'], sps, sps);
  sps['long_term_ref_pics_present_flag'] = bs.u(1);
  if (sps['long_term_ref_pics_present_flag']) {
    sps['num_long_term_ref_pics_sps'] = bs.ue();
    for (var i = 0; i < sps['num_long_term_ref_pics_sps']; i++) {
      sps['lt_ref_pic_poc_lsb_sps[' + i + ']'] =
          bs.u(sps['log2_max_pic_order_cnt_lsb_minus4'] + 4);
      sps['used_by_curr_pic_lt_sps_flag[' + i + ']'] = bs.u(1);
    }
  }
  sps['sps_temporal_mvp_enabled_flag'] = bs.u(1);
  sps['strong_intra_smoothing_enabled_flag'] = bs.u(1);
  sps['vui_parameters_present_flag'] = bs.u(1);
  if (sps['vui_parameters_present_flag']) {
    sps['aspect_ratio_info_present_flag'] = bs.u(1);
    if (sps['aspect_ratio_info_present_flag']) {
      sps['aspect_ratio_idc'] = bs.u(8);
      if (sps['aspect_ratio_idc'] == 255) {
        sps['sar_width'] = bs.u(16);
        sps['sar_height'] = bs.u(16);
      }
    }
    sps['overscan_info_present_flag'] = bs.u(1);
    if (sps['overscan_info_present_flag'])
      sps['overscan_appropriate_flag'] = bs.u(1);
    sps['video_signal_type_present_flag'] = bs.u(1);
    if (sps['video_signal_type_present_flag']) {
      sps['video_format'] = bs.u(3);
      sps['video_full_range_flag'] = bs.u(1);
      sps['colour_description_present_flag'] = bs.u(1);
      if (sps['colour_description_present_flag']) {
        sps['colour_primaries'] = bs.u(8);
        sps['transfer_characteristics'] = bs.u(8);
        sps['matrix_coeffs'] = bs.u(8);
      }
    }
    sps['chroma_loc_info_present_flag'] = bs.u(1);
    if (sps['chroma_loc_info_present_flag']) {
      sps['chroma_sample_loc_type_top_field'] = bs.ue();
      sps['chroma_sample_loc_type_bottom_field'] = bs.ue();
    }
    sps['neutral_chroma_indication_flag'] = bs.u(1);
    sps['field_seq_flag'] = bs.u(1);
    sps['frame_field_info_present_flag'] = bs.u(1);
    sps['default_display_window_flag'] = bs.u(1);
    if (sps['default_display_window_flag']) {
      sps['def_disp_win_left_offset'] = bs.ue();
      sps['def_disp_win_right_offset'] = bs.ue();
      sps['def_disp_win_top_offset'] = bs.ue();
      sps['def_disp_win_bottom_offset'] = bs.ue();
    }
    sps['vui_timing_info_present_flag'] = bs.u(1);
    if (sps['vui_timing_info_present_flag']) {
      sps['vui_num_units_in_tick'] = bs.u(32);
      sps['vui_time_scale'] = bs.u(32);
      sps['vui_poc_proportional_to_timing_flag'] = bs.u(1);
      if (sps['vui_poc_proportional_to_timing_flag'])
        sps['vui_num_ticks_poc_diff_one_minus1'] = bs.ue();
      sps['vui_hrd_parameters_present_flag'] = bs.u(1);
      if (sps['vui_hrd_parameters_present_flag'])
        this.hrd_parameters(bs, '', 1, sps['sps_max_sub_layers_minus1'], sps);
    }
    sps['bitstream_restriction_flag'] = bs.u(1);
    if (sps['bitstream_restriction_flag']) {
      sps['tiles_fixed_structure_flag'] = bs.u(1);
      sps['motion_vectors_over_pic_boundaries_flag'] = bs.u(1);
      sps['restricted_ref_pic_lists_flag'] = bs.u(1);
      sps['min_spatial_segmentation_idc'] = bs.ue();
      sps['max_bytes_per_pic_denom'] = bs.ue();
      sps['max_bits_per_min_cu_denom'] = bs.ue();
      sps['log2_max_mv_length_horizontal'] = bs.ue();
      sps['log2_max_mv_length_vertical'] = bs.ue();
    }
  }
  sps['sps_extension_flag'] = bs.u(1);
  if (sps['sps_extension_flag']) {
    sps['sps_range_extension_flag'] = bs.u(1);
    sps['sps_multilayer_extension_flag'] = bs.u(1);
    sps['sps_3d_extension_flag'] = bs.u(1);
    sps['sps_extension_5bits'] = bs.u(5);
  }
  if (sps['sps_range_extension_flag']) {
    sps['transform_skip_rotation_enabled_flag'] = bs.u(1);
    sps['transform_skip_context_enabled_flag'] = bs.u(1);
    sps['implicit_rdpcm_enabled_flag'] = bs.u(1);
    sps['explicit_rdpcm_enabled_flag'] = bs.u(1);
    sps['extended_precision_processing_flag'] = bs.u(1);
    sps['intra_smoothing_disabled_flag'] = bs.u(1);
    sps['high_precision_offsets_enabled_flag'] = bs.u(1);
    sps['persistent_rice_adaptation_enabled_flag'] = bs.u(1);
    sps['cabac_bypass_alignment_enabled_flag'] = bs.u(1);
  }
  if (sps['sps_multilayer_extension_flag']) {
    sps['inter_view_mv_vert_constraint_flag'] = bs.u(1);
  }
  if (sps['sps_3d_extension_flag']) {
    for (var d = 0; d <= 1; d++) {
      sps['iv_di_mc_enabled_flag[' + d + ']'] = bs.u(1);
      sps['iv_mv_scal_enabled_flag[' + d + ']'] = bs.u(1);
      if (d == 0) {
        sps['log2_ivmc_sub_pb_size_minus3'] = bs.ue();
        sps['iv_res_pred_enabled_flag'] = bs.u(1);
        sps['depth_ref_enabled_flag'] = bs.u(1);
        sps['vsp_mc_enabled_flag'] = bs.u(1);
        sps['dbbp_enabled_flag'] = bs.u(1);
      } else {
        sps['tex_mc_enabled_flag'] = bs.u(1);
        sps['log2_texmc_sub_pb_size_minus3'] = bs.ue();
        sps['intra_contour_enabled_flag'] = bs.u(1);
        sps['intra_dc_only_wedge_enabled_flag'] = bs.u(1);
        sps['cqt_cu_part_pred_enabled_flag'] = bs.u(1);
        sps['inter_dc_only_enabled_flag'] = bs.u(1);
        sps['skip_intra_enabled_flag'] = bs.u(1);
      }
    }
  }
  if (sps['sps_extension_5bits']) {
    for (var i = 0; more_rbsp_data(bs); i++)
      sps['sps_extension_5bits[' + i + ']'] = bs.u(1);
  }
};

bitstream_parser_h265.prototype.colour_mapping_octants = function(
    pps, inpDepth, idxY, idxCb, idxCr, inpLength) {
  if (inpDepth < pps['cm_octant_depth'])
    pps['split_octant_flag[' + inpDepth + ']'] = bs.u(1);
  if (pps['split_octant_flag[' + inpDepth + ']'])
    for (var k = 0; k < 2; k++)
      for (var m = 0; m < 2; m++)
        for (var n = 0; n < 2; n++)
          this.colour_mapping_octants(
              pps, inpDepth + 1, idxY + PartNumY * k * inpLength / 2,
              idxCb + m * inpLength / 2, idxCr + n * inpLength / 2,
              inpLength / 2);
  else
    for (var i = 0; i < 1 << pps['cm_y_part_num_log2']; i++) {
      var idxShiftY = idxY + (i << (pps['cm_octant_depth'] - inpDepth));
      for (var j = 0; j < 4; j++) {
        var coded_res_flag =
            pps['coded_res_flag[' + idxShiftY + '][' + idxCb + '][' + idxCr +
                '][' + j + ']'] = bs.u(1);
        if (coded_res_flag) {
          for (var c = 0; c < 3; c++) {
            var res_coeff_q =
                pps['res_coeff_q[' + idxShiftY + '][' + idxCb + '][' + idxCr +
                    '][' + j + '][' + c + ']'] = bs.ue();
            var res_coeff_r =
                pps['res_coeff_r[' + idxShiftY + '][' + idxCb + '][' + idxCr +
                    '][' + j + '][' + c + ']'] = bs.ue();
            if (res_coeff_q || res_coeff_r)
              pps['res_coeff_s[' + idxShiftY + '][' + idxCb + '][' + idxCr +
                  '][' + j + '][' + c + ']'] = bs.u(1);
          }
        }
      }
    }
};

bitstream_parser_h265.prototype.delta_dlt = function(pps, i) {
  pps['num_val_delta_dlt[' + i + ']'] =
      bs.u(pps['pps_bit_depth_for_depth_layers_minus8'] + 8);
  if (pps['num_val_delta_dlt[' + i + ']'] > 0) {
    if (pps['num_val_delta_dlt[' + i + ']'] > 1)
      pps['max_diff[' + i + ']'] =
          bs.u(pps['pps_bit_depth_for_depth_layers_minus8'] + 8);
    var min_diff_minus1 = pps['max_diff[' + i + ']'] - 1;
    if (pps['num_val_delta_dlt[' + i + ']'] > 2 &&
        pps['max_diff[' + i + ']'] > 0)
      min_diff_minus1 = pps['min_diff_minus1[' + i + ']'] =
          bs.u(this.cntbits(pps['max_diff[' + i + ']']));
    pps['delta_dlt_val0[' + i + ']'] =
        bs.u(pps['pps_bit_depth_for_depth_layers_minus8'] + 8);
    if (pps['max_diff[' + i + ']'] > min_diff_minus1 + 1) {
      var nbits =
          this.cntbits(pps['max_diff[' + i + ']'] - min_diff_minus1 + 2);
      for (var k = 1; k < pps['num_val_delta_dlt[' + i + ']']; k++)
        pps['delta_val_diff_minus_min[' + k + ']'] = bs.u(nbits);
    }
  }
};

bitstream_parser_h265.prototype.parse_pps = function(bs, pps) {
  pps['pps_pic_parameter_set_id'] = bs.ue();
  pps['pps_seq_parameter_set_id'] = bs.ue();
  pps['dependent_slice_segments_enabled_flag'] = bs.u(1);
  pps['output_flag_present_flag'] = bs.u(1);
  pps['num_extra_slice_header_bits'] = bs.u(3);
  pps['sign_data_hiding_enabled_flag'] = bs.u(1);
  pps['cabac_init_present_flag'] = bs.u(1);
  pps['num_ref_idx_l0_default_active_minus1'] = bs.ue();
  pps['num_ref_idx_l1_default_active_minus1'] = bs.ue();
  pps['init_qp_minus26'] = bs.se();
  pps['constrained_intra_pred_flag'] = bs.u(1);
  pps['transform_skip_enabled_flag'] = bs.u(1);
  pps['cu_qp_delta_enabled_flag'] = bs.u(1);
  if (pps['cu_qp_delta_enabled_flag']) pps['diff_cu_qp_delta_depth'] = bs.ue();
  pps['pps_cb_qp_offset'] = bs.se();
  pps['pps_cr_qp_offset'] = bs.se();
  pps['pps_slice_chroma_qp_offsets_present_flag'] = bs.u(1);
  pps['weighted_pred_flag'] = bs.u(1);
  pps['weighted_bipred_flag'] = bs.u(1);
  pps['transquant_bypass_enabled_flag'] = bs.u(1);
  pps['tiles_enabled_flag'] = bs.u(1);
  pps['entropy_coding_sync_enabled_flag'] = bs.u(1);
  if (pps['tiles_enabled_flag']) {
    pps['num_tile_columns_minus1'] = bs.ue();
    pps['num_tile_rows_minus1'] = bs.ue();
    pps['uniform_spacing_flag'] = bs.u(1);
    if (pps['uniform_spacing_flag'] == 0) {
      for (var i = 0; i < pps['num_tile_columns_minus1']; i++)
        pps['column_width_minus1[' + i + ']'] = bs.ue();
      for (var i = 0; i < pps['num_tile_rows_minus1']; i++)
        pps['row_height_minus1[' + i + ']'] = bs.ue();
    }
    pps['loop_filter_across_tiles_enabled_flag'] = bs.u(1);
  }
  pps['pps_loop_filter_across_slices_enabled_flag'] = bs.u(1);
  pps['deblocking_filter_control_present_flag'] = bs.u(1);
  if (pps['deblocking_filter_control_present_flag']) {
    pps['deblocking_filter_override_enabled_flag'] = bs.u(1);
    pps['pps_deblocking_filter_disabled_flag'] = bs.u(1);
    if (pps['pps_deblocking_filter_disabled_flag'] == 0) {
      pps['pps_beta_offset_div2'] = bs.se();
      pps['pps_tc_offset_div2'] = bs.se();
    }
  }
  pps['pps_scaling_list_data_present_flag'] = bs.u(1);
  if (pps['pps_scaling_list_data_present_flag'])
    this.scaling_list_data(bs, pps);
  pps['lists_modification_present_flag'] = bs.u(1);
  pps['log2_parallel_merge_level_minus2'] = bs.ue();
  pps['slice_segment_header_extension_present_flag'] = bs.u(1);
  pps['pps_extension_present_flag'] = bs.u(1);
  if (pps['pps_extension_present_flag']) {
    pps['pps_range_extension_flag'] = bs.u(1);
    pps['pps_multilayer_extension_flag'] = bs.u(1);
    pps['pps_3d_extension_flag'] = bs.u(1);
    pps['pps_extension_5bits'] = bs.u(5);
  }
  if (pps['pps_range_extension_flag']) {
    if (pps['transform_skip_enabled_flag'])
      pps['log2_max_transform_skip_block_size_minus2'] = bs.ue();
    pps['cross_component_prediction_enabled_flag'] = bs.u(1);
    pps['chroma_qp_offset_list_enabled_flag'] = bs.u(1);
    if (pps['chroma_qp_offset_list_enabled_flag']) {
      pps['diff_cu_chroma_qp_offset_depth'] = bs.ue();
      pps['chroma_qp_offset_list_len_minus1'] = bs.ue();
      for (var i = 0; i <= pps['chroma_qp_offset_list_len_minus1']; i++) {
        pps['cb_qp_offset_list[' + i + ']'] = bs.se();
        pps['cr_qp_offset_list[' + i + ']'] = bs.se();
      }
    }
    pps['log2_sao_offset_scale_luma'] = bs.ue();
    pps['log2_sao_offset_scale_chroma'] = bs.ue();
  }
  if (pps['pps_multilayer_extension_flag']) {
    pps['poc_reset_info_present_flag'] = bs.u(1);
    pps['pps_infer_scaling_list_flag'] = bs.u(1);
    if (pps['pps_infer_scaling_list_flag'])
      pps['pps_scaling_list_ref_layer_id'] = bs.u(6);
    pps['num_ref_loc_offsets'] = bs.ue();
    for (var i = 0; i < pps['num_ref_loc_offsets']; i++) {
      pps['ref_loc_offset_layer_id[' + i + ']'] = bs.u(6);
      pps['scaled_ref_layer_offset_present_flag[' + i + ']'] = bs.u(1);
      if (pps['scaled_ref_layer_offset_present_flag[' + i + ']']) {
        pps['scaled_ref_layer_left_offset[ ref_loc_offset_layer_id[' + i +
            ']]'] = bs.se();
        pps['scaled_ref_layer_top_offset[ ref_loc_offset_layer_id[' + i +
            ']]'] = bs.se();
        pps['scaled_ref_layer_right_offset[ ref_loc_offset_layer_id[' + i +
            ']]'] = bs.se();
        pps['scaled_ref_layer_bottom_offset[ ref_loc_offset_layer_id[' + i +
            ']]'] = bs.se();
      }
      pps['ref_region_offset_present_flag[' + i + ']'] = bs.u(1);
      if (pps['ref_region_offset_present_flag[' + i + ']']) {
        pps['ref_region_left_offset[ ref_loc_offset_layer_id[' + i + ']]'] =
            bs.se();
        pps['ref_region_top_offset[ ref_loc_offset_layer_id[' + i + ']]'] =
            bs.se();
        pps['ref_region_right_offset[ ref_loc_offset_layer_id[' + i + ']]'] =
            bs.se();
        pps['ref_region_bottom_offset[ ref_loc_offset_layer_id[' + i + ']]'] =
            bs.se();
      }
      pps['resample_phase_set_present_flag[' + i + ']'] = bs.u(1);
      if (pps['resample_phase_set_present_flag[' + i + ']']) {
        pps['phase_hor_luma[ ref_loc_offset_layer_id[' + i + ']]'] = bs.ue();
        pps['phase_ver_luma[ ref_loc_offset_layer_id[' + i + ']]'] = bs.ue();
        pps['phase_hor_chroma_plus8[ ref_loc_offset_layer_id[' + i + ']]'] =
            bs.ue();
        pps['phase_ver_chroma_plus8[ ref_loc_offset_layer_id[' + i + ']]'] =
            bs.ue();
      }
    }
    pps['colour_mapping_enabled_flag'] = bs.u(1);
    if (pps['colour_mapping_enabled_flag']) {
      pps['num_cm_ref_layers_minus1'] = bs.ue();
      for (var i = 0; i <= pps['num_cm_ref_layers_minus1']; i++)
        pps['cm_ref_layer_id[' + i + ']'] = bs.u(6);
      pps['cm_octant_depth'] = bs.u(2);
      pps['cm_y_part_num_log2'] = bs.u(2);
      pps['luma_bit_depth_cm_input_minus8'] = bs.ue();
      pps['chroma_bit_depth_cm_input_minus8'] = bs.ue();
      pps['luma_bit_depth_cm_output_minus8'] = bs.ue();
      pps['chroma_bit_depth_cm_output_minus8'] = bs.ue();
      pps['cm_res_quant_bits'] = bs.u(2);
      pps['cm_delta_flc_bits_minus1'] = bs.u(2);
      if (pps['cm_octant_depth'] == 1) {
        pps['cm_adapt_threshold_u_delta'] = bs.se();
        pps['cm_adapt_threshold_v_delta'] = bs.se();
      }
      this.colour_mapping_octants(pps, 0, 0, 0, 0, 1 << pps['cm_octant_depth']);
    }
  }
  if (pps['pps_3d_extension_flag']) {
    pps['dlts_present_flag'] = bs.u(1);
    if (pps['dlts_present_flag']) {
      pps['pps_depth_layers_minus1'] = bs.u(6);
      pps['pps_bit_depth_for_depth_layers_minus8'] = bs.u(4);
      for (var i = 0; i <= pps['pps_bit_depth_for_depth_layers_minus8']; i++) {
        pps['dlt_flag[' + i + ']'] = bs.u(1);
        if (pps['dlt_flag[' + i + ']']) {
          pps['dlt_pred_flag[' + i + ']'] = bs.u(1);
          if (!pps['dlt_pred_flag[' + i + ']'])
            pps['dlt_val_flags_present_flag[' + i + ']'] = bs.u(1);
          if (pps['dlt_val_flags_present_flag[' + i + ']'])
            for (var j = 0; j <=
                 (1 << (pps['pps_bit_depth_for_depth_layers_minus8'] + 8)) - 1;
                 j++)
              pps['dlt_value_flag[' + i + '][' + j + ']'] = bs.u(1);
          else
            this.delta_dlt(pps, i);
        }
      }
    }
  }
  if (pps['pps_extension_5bits']) {
    for (var i = 0; more_rbsp_data(bs); i++)
      pps['pps_extension_data_flag[' + i + ']'] = bs.u(1);
  }
};

bitstream_parser_h265.prototype.slice_segment_header = function(bs, sh) {
  sh['first_slice_segment_in_pic_flag'] = bs.u(1);
  if (sh['nal_unit_type'] >= 16 && sh['nal_unit_type'] <= 23)
    sh['no_output_of_prior_pics_flag'] = bs.u(1);
  sh['slice_pic_parameter_set_id'] = bs.ue();

  this.pps = this.find_nalu(
      [34], 'pps_pic_parameter_set_id', sh['slice_pic_parameter_set_id']);
  if (this.pps == null) return sh;

  this.sps = this.find_nalu(
      [33], 'sps_seq_parameter_set_id', this.pps['pps_seq_parameter_set_id']);

  if (sh['first_slice_segment_in_pic_flag'] == 0) {
    if (this.pps['dependent_slice_segments_enabled_flag'])
      sh['dependent_slice_segment_flag'] = bs.u(1);
    var MaxCUWidth = 1
        << (this.sps['log2_min_luma_coding_block_size_minus3'] + 3 +
            this.sps['log2_diff_max_min_luma_coding_block_size']);
    var NumCTUs = Math.floor(
                      (this.sps['pic_width_in_luma_samples'] + MaxCUWidth - 1) /
                      MaxCUWidth) *
        Math.floor(
            (this.sps['pic_height_in_luma_samples'] + MaxCUWidth - 1) /
            MaxCUWidth);
    var n = 0;
    while (NumCTUs > (1 << n)) n++;
    sh['slice_segment_address'] = bs.u(n);
  }

  if (!sh['dependent_slice_segment_flag']) {
    for (var i = 0; i < this.pps['num_extra_slice_header_bits']; i++)
      sh['slice_reserved_flag[' + i + ']'] = bs.u(1);
    sh['slice_type'] = bs.ue();
    if (this.pps['output_flag_present_flag']) sh['pic_output_flag'] = bs.u(1);

    if (this.sps == null) return sh;

    if (this.sps['separate_colour_plane_flag']) sh['colour_plane_id'] = bs.u(2);

    var NumPicTotalCurr = 0;
    if (sh['nal_unit_type'] != 19 && sh['nal_unit_type'] != 20) {
      sh['slice_pic_order_cnt_lsb'] =
          bs.u(this.sps['log2_max_pic_order_cnt_lsb_minus4'] + 4);
      sh['short_term_ref_pic_set_sps_flag'] = bs.u(1);
      if (sh['short_term_ref_pic_set_sps_flag'] == 0) {
        this.short_term_ref_pic_set(
            bs, this.sps['num_short_term_ref_pic_sets'],
            this.sps['num_short_term_ref_pic_sets'], sh, this.sps);
        NumPicTotalCurr = sh['#NumDeltaPocs'];
      } else if (this.sps['num_short_term_ref_pic_sets'] > 1) {
        sh['short_term_ref_pic_set_idx'] =
            bs.u(cntbits(this.sps['num_short_term_ref_pic_sets']));
        NumPicTotalCurr =
            this.sps['#NumDeltaPocs[' + sh['short_term_ref_pic_set_idx'] + ']'];
      }

      if (this.sps['long_term_ref_pics_present_flag']) {
        var num_long_term_sps = 0;
        if (this.sps['num_long_term_ref_pics_sps'] > 0)
          sh['num_long_term_sps'] = num_long_term_sps = bs.ue();
        sh['num_long_term_pics'] = bs.ue();
        var nbits = cntbits(this.sps['num_long_term_ref_pics_sps']);
        for (var i = 0; i < num_long_term_sps + sh['num_long_term_pics']; i++) {
          if (i < num_long_term_sps) {
            if (this.sps['num_long_term_ref_pics_sps'] > 1) {
              sh['lt_idx_sps[' + i + ']'] = bs.u(nbits);
              NumPicTotalCurr += this.sps
                                     ['used_by_curr_pic_lt_sps_flag[' +
                                      sh['lt_idx_sps[' + i + ']'] + ']'];
            }
          } else {
            sh['poc_lsb_lt[' + i + ']'] =
                bs.u(this.sps['log2_max_pic_order_cnt_lsb_minus4'] + 4);
            sh['used_by_curr_pic_lt_flag[' + i + ']'] = bs.u(1);
            NumPicTotalCurr += sh['used_by_curr_pic_lt_flag[' + i + ']'];
          }
          sh['delta_poc_msb_present_flag[' + i + ']'] = bs.u(1);
          if (sh['delta_poc_msb_present_flag[' + i + ']'])
            sh['delta_poc_msb_cycle_lt[' + i + ']'] = bs.ue();
        }
      }

      if (this.sps['sps_temporal_mvp_enabled_flag'])
        sh['slice_temporal_mvp_enabled_flag'] = bs.u(1);
    }

    if (this.sps['sample_adaptive_offset_enabled_flag']) {
      sh['slice_sao_luma_flag'] = bs.u(1);
      if (this.sps['chroma_format_idc'] > 0)
        sh['slice_sao_chroma_flag'] = bs.u(1);
    }

    if (sh['slice_type'] == 1 || sh['slice_type'] == 0) {
      sh['num_ref_idx_active_override_flag'] = bs.u(1);
      var num_ref_idx_l0_active_minus1 =
          this.pps['num_ref_idx_l0_default_active_minus1'];
      var num_ref_idx_l1_active_minus1 =
          this.pps['num_ref_idx_l1_default_active_minus1'];
      if (sh['num_ref_idx_active_override_flag']) {
        sh['num_ref_idx_l0_active_minus1'] = num_ref_idx_l0_active_minus1 =
            bs.ue();
        if (sh['slice_type'] == 0)
          sh['num_ref_idx_l1_active_minus1'] = num_ref_idx_l1_active_minus1 =
              bs.ue();
      }
      if (this.pps['lists_modification_present_flag'] && NumPicTotalCurr > 1) {
        var nbits = cntbits(NumPicTotalCurr);
        sh['ref_pic_list_modification_flag_l0'] = bs.u(1);
        if (sh['ref_pic_list_modification_flag_l0']) {
          for (var i = 0; i <= num_ref_idx_l0_active_minus1; i++)
            sh['list_entry_l0[' + i + ']'] = bs.u(nbits);
        }
        if (sh['slice_type'] == 0) {
          sh['ref_pic_list_modification_flag_l1'] = bs.u(1);
          if (sh['ref_pic_list_modification_flag_l1']) {
            for (var i = 0; i <= num_ref_idx_l1_active_minus1; i++)
              sh['list_entry_l1[' + i + ']'] = bs.u(nbits);
          }
        }
      }
      if (sh['slice_type'] == 0) sh['mvd_l1_zero_flag'] = bs.u(1);
      if (this.pps['cabac_init_present_flag']) sh['cabac_init_flag'] = bs.u(1);
      if (sh['slice_temporal_mvp_enabled_flag']) {
        var collocated_from_l0_flag = 1;
        if (sh['slice_type'] == 0)
          sh['collocated_from_l0_flag'] = collocated_from_l0_flag = bs.u(1);
        if ((collocated_from_l0_flag && num_ref_idx_l0_active_minus1 > 0) ||
            (collocated_from_l0_flag == 0 && num_ref_idx_l1_active_minus1 > 0))
          sh['collocated_ref_idx'] = bs.ue();
      }
      if ((this.pps['weighted_pred_flag'] && sh['slice_type'] == 1) ||
          (this.pps['weighted_bipred_flag'] && sh['slice_type'] == 0)) {
        sh['luma_log2_weight_denom'] = bs.ue();
        if ('chroma_format_idc' in this.sps &&
            this.sps['chroma_format_idc'] != 0)
          sh['delta_chroma_log2_weight_denom'] = bs.se();
        for (var i = 0; i <= num_ref_idx_l0_active_minus1; i++)
          sh['luma_weight_l0_flag[' + i + ']'] = bs.u(1);
        if (this.sps['chroma_format_idc'] != 0) {
          for (var i = 0; i <= num_ref_idx_l0_active_minus1; i++)
            sh['chroma_weight_l0_flag[' + i + ']'] = bs.u(1);
        }
        for (var i = 0; i <= num_ref_idx_l0_active_minus1; i++) {
          if (sh['luma_weight_l0_flag[' + i + ']']) {
            sh['delta_luma_weight_l0[' + i + ']'] = bs.se();
            sh['luma_offset_l0[' + i + ']'] = bs.se();
          }
          if (sh['chroma_weight_l0_flag[' + i + ']']) {
            for (var j = 0; j < 2; j++) {
              sh['delta_chroma_weight_l0[' + i + '][' + j + ']'] = bs.se();
              sh['delta_chroma_offset_l0[' + i + '][' + j + ']'] = bs.se();
            }
          }
        }
        if (sh['slice_type'] == 0) {
          for (var i = 0; i <= num_ref_idx_l1_active_minus1; i++)
            sh['luma_weight_l1_flag[' + i + ']'] = bs.u(1);
          if (this.sps['chroma_format_idc'] != 0)
            for (var i = 0; i <= num_ref_idx_l1_active_minus1; i++)
              sh['chroma_weight_l1_flag[' + i + ']'] = bs.u(1);
          for (var i = 0; i <= num_ref_idx_l1_active_minus1; i++) {
            if (sh['luma_weight_l1_flag[' + i + ']']) {
              sh['delta_luma_weight_l1[' + i + ']'] = bs.se();
              sh['luma_offset_l1[' + i + ']'] = bs.se();
            }
            if (sh['chroma_weight_l1_flag[' + i + ']']) {
              for (var j = 0; j < 2; j++) {
                sh['delta_chroma_weight_l1[' + i + '][' + j + ']'] = bs.se();
                sh['delta_chroma_offset_l1[' + i + '][' + j + ']'] = bs.se();
              }
            }
          }
        }
      }
      sh['five_minus_max_num_merge_cand'] = bs.ue();
    }

    sh['slice_qp_delta'] = bs.se();
    if (this.pps['pps_slice_chroma_qp_offsets_present_flag']) {
      sh['slice_cb_qp_offset'] = bs.se();
      sh['slice_cr_qp_offset'] = bs.se();
    }

    if (this.pps['deblocking_filter_override_enabled_flag'])
      sh['deblocking_filter_override_flag'] = bs.u(1);
    if (sh['deblocking_filter_override_flag'] || 0) {
      sh['slice_deblocking_filter_disabled_flag'] = bs.u(1);
      if (sh['slice_deblocking_filter_disabled_flag'] == 0) {
        sh['slice_beta_offset_div2'] = bs.se();
        sh['slice_tc_offset_div2'] = bs.se();
      }
    }

    if (this.pps['pps_loop_filter_across_slices_enabled_flag'] &&
        (sh['slice_sao_luma_flag'] || sh['slice_sao_chroma_flag'] ||
         (sh['slice_deblocking_filter_disabled_flag'] || 0) == 0))
      sh['slice_loop_filter_across_slices_enabled_flag'] = bs.u(1);
  }

  if (this.pps['tiles_enabled_flag'] ||
      this.pps['entropy_coding_sync_enabled_flag']) {
    sh['num_entry_point_offsets'] = bs.ue();
    if (sh['num_entry_point_offsets'] > 0) {
      sh['offset_len_minus1'] = bs.ue();
      for (var i = 0; i < sh['num_entry_point_offsets']; i++)
        sh['entry_point_offset_minus1[' + i + ']'] =
            bs.u(sh['offset_len_minus1'] + 1);
    }
  }

  if (this.pps['slice_segment_header_extension_present_flag']) {
    sh['slice_segment_header_extension_length'] = bs.ue();
    for (var i = 0; i < sh['slice_segment_header_extension_length']; i++)
      sh['slice_segment_header_extension_data_byte[' + i + ']'] = bs.u(8);
  }
};

bitstream_parser_h265.prototype.parse_sei = function(bs) {
  var seis = {};
  return seis;
};