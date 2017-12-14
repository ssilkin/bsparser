function create_parser(fmt) {
  if (fmt == 'ivf')
    return new file_parser_ivf();
  else if (fmt == '264')
    return new file_parser_annexb();
  return null;
}

function bitstream(buffer) {
  this.buffer = buffer;
  this.length = (buffer instanceof Array) ? buffer.length : buffer.byteLength;
  this.bytepos = 0;
  this.bits = 0;
  this.nbits = 0;

  this.load = function () {
    while (this.nbits <= 24 && this.bytepos < this.length) {
      var onebyte = this.buffer[this.bytepos++];
      this.bits |= onebyte << (24 - this.nbits);
      this.nbits += 8;
    }
  }

  this.bitpos = function () {
    return 8 * this.bytepos - this.nbits;
  }

  this.u = function (n) {
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
  }

  this.s = function (n) {
    var val = this.u(n);
    var sign = this.u(1);
    return sign ? -val : val;
  }

  this.ue = function () {
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
  }

  this.se = function () {
    var codenum = this.ue();
    var codeval = (codenum + 1) >> 1;
    return (codenum & 1) ? codeval : -codeval;
  }
}

function int2str(x, base, length, padding) {
  var str = x.toString(base);
  var pad = Array(length - str.length + 1).join(padding);
  return pad + str;
}

function more_rbsp_data(bs) {
  return bs.bitpos() + 1 < bs.stopbit;
}

function bytes2str(bytes) {
  var str = '';
  for (var i = 0; i < bytes.length; i++)
    str += String.fromCharCode(bytes[i]);
  return str;
}

function bytes2word(buffer, offset) {
  return (buffer[offset + 1] << 8) | buffer[offset + 0];
}

function bytes2dword(buffer, offset) {
  return (buffer[offset + 3] << 24) | (buffer[offset + 2] << 16)
    | (buffer[offset + 1] << 8) | buffer[offset];
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

  this.store = function (h) {
    h['@id'] = this.header.length;
    this.header.push(h);
  }

  this.next = function () {
    if (this.last < this.header.length)
      return this.header[this.last++];
    if (this.parser)
      return this.parser.next();
    return null;
  }

  this.get = function (id) {
    if (id >= this.idoff)
      return this.parser.get(id);
    return this.header[id];
  }
}

function file_parser_ivf() {
  file_parser_base.call(this);
  this.goto = 2;
  this.need = 8;
}

file_parser_ivf.prototype = new file_parser_base();
file_parser_ivf.prototype.parse = function (buffer) {
  if (buffer == null)
    return;
  var pos = 0;
  while (pos < buffer.length) {
    if (this.need > 0) {
      this.buffer[this.recv++] = buffer[pos++];
      this.need--;
    }
    if (this.need)
      continue;

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
        this.parser = new file_parser_annexb();
      else
        alert('unknown fourcc ' + h['fourcc']);
      this.store(h);
      this.need = 12;
      this.goto = 1;
    }
    this.addr += this.recv;
    this.recv = 0;
  }
}

file_parser_ivf.prototype.ivf_header = function (buffer, addr) {
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
  h['@extra'] = h["fourcc"]
    + " " + h["width"] + 'x' + h["height"];
  return h;
}

function file_parser_annexb() {
  file_parser_base.call(this);
  this.code = 0xffffffff;
  this.first = true;
  this.parser = new bitstream_parser_h264(this.idoff);
}

file_parser_annexb.prototype = new file_parser_base();
file_parser_annexb.prototype.parse = function (buffer, addr) {
  if (buffer == null)
    return;

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
        this.parser.parse(this.buffer.slice(0, this.recv), this.addr);
        this.addr += this.recv + cnt3;
        this.recv = 0;
        cnt3 = 0;
      }
    }
  }
}

function bitstream_parser_base(idoff) {
  this.idoff = idoff;
  this.header = [];
  this.last = 0;

  this.next = function () {
    if (this.last < this.header.length)
      return this.header[this.last++];
    return null;
  }

  this.get = function (id) {
    return this.header[id - this.idoff];
  }

  this.store = function (h) {
    h['@id'] = this.header.length + this.idoff;
    this.header.push(h);
  }
}

function bitstream_parser_vp8(idoff) {
  bitstream_parser_base.call(this, idoff);
}

bitstream_parser_vp8.prototype = new bitstream_parser_base();
bitstream_parser_vp8.prototype.parse = function (buffer, addr) {
  var bs = new bitstream(buffer);
  var h = {};
  var byte = bs.u(8);
  h['frame_type'] = byte & 1;
  h['version'] = (byte >> 1) & 7;
  h['show_frame'] = (byte >> 4) & 1;
  h['partition_length'] = (byte | (bs.u(8) << 8) | (bs.u(8) << 16)) >> 5;
  if (h['frame_type'] == 0) {
    h['sync_code'] = '0x' + int2str(bs.u(24), 16, 6, 0);
    h['width'] = (bs.u(8) | (bs.u(8) << 8)) & 0x3fff;
    h['height'] = (bs.u(8) | (bs.u(8) << 8)) & 0x3fff;
  }
  h['@addr'] = addr;
  h['@type'] = h['frame_type'] == 0 ? 'I' : 'P';
  h['@length'] = buffer.length;
  h['@keyframe'] = 1 - h['frame_type'];
  this.store(h);
}

function bitstream_parser_vp9(idoff) {
  bitstream_parser_base.call(this, idoff);
}

bitstream_parser_vp9.prototype = new bitstream_parser_base();
bitstream_parser_vp9.prototype.parse = function (buffer, addr) {
  var bs = new bitstream(buffer);
  var h = {};
  var ref_idx = 0;
  h['frame_marker'] = bs.u(2);
  h['profile'] = bs.u(1) + (bs.u(1) << 1);
  if (h['profile'] == 3)
    h['reserved_zero'] = bs.u(1);
  h['show_existing_frames'] = bs.u(1);
  if (h['show_existing_frames'])
    h['frame_to_show_map_idx'] = bs.u(3);
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
    if (h['show_frame'] == 0)
      h['intra_only'] = bs.u(1);
    if (h['error_resilient_mode'] == 0)
      h['reset_frame_context'] = bs.u(2);
    if (h['intra_only'] || 0) {
      h['frame_sync_bytes'] = bs.u(8) + ', ' + bs.u(8) + ', ' + bs.u(8);
      if (h['profile'] > 0) {
        this.color_config(h, bs);
        h['refresh_frame_flags'] = bs.u(8);
        h['frame_width_minus_1'] = bs.u(16);
        h['frame_height_minus_1'] = bs.u(16);
        h['render_and_frame_size_different'] = bs.u(1);
        if (h['render_and_frame_size_different'] == 1) {
          h['render_width_minus_1'] = bs.u(16);
          h['render_height_minus_1'] = bs.u(16);
        }
      }
    } else {
      h['refresh_frame_flags'] = bs.u(8);
      for (var i = 0; i < 3; i++) {
        h['ref_frame_idx[' + i + ']'] = bs.u(3);
        h['ref_frame_sign_bias[' + i + ']'] = bs.u(1);
      }
      for (ref_idx = 0; ref_idx < 3; ref_idx++) {
        h['found_ref[' + ref_idx + ']'] = bs.u(1);
        if (h['found_ref[' + ref_idx + ']'])
          break;
      }
      if (ref_idx == 3) {
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
    if (h['delta_coded[' + i + ']'])
      h['delta_q[' + i + ']'] = bs.s(4);
  }

  h['segmentation_enabled'] = bs.u(1);
  if (h['segmentation_enabled']) {
    h['segmentation_update_map'] = bs.u(1);
    if (h['segmentation_update_map']) {
      for (var i = 0; i < 7; i++) {
        h['prob_coded[' + i + ']'] = bs.u(1);
        if (h['prob_coded[' + i + ']'])
          h['prob[' + i + ']'] = bs.u(8);
      }
      h['segmentation_temporal_update'] = bs.u(1);
      if (h['segmentation_temporal_update']) {
        for (var i = 0; i < 7; i++) {
          h['prob_coded[' + i + ']'] = bs.u(1);
          if (h['prob_coded[' + i + ']'])
            h['prob[' + i + ']'] = bs.u(8);
        }
      }
      h['segmentation_update_data'] = bs.u(1);
      if (h['segmentation_update_data']) {
        var MAX_SEGMENTS = 8;
        var SEG_LVL_MAX = 4;
        var segmentation_feature_bits = [8, 6, 2, 0];
        var segmentation_feature_signed = [1, 1, 0, 0];
        h['segmentation_abs_or_delta_update'] = bs.u(1);
        for (var i = 0; i < MAX_SEGMENTS; i++) {
          for (var j = 0; j < SEG_LVL_MAX; j++) {
            h['feature_enabled[' + i + '][' + j + ']'] = bs.u(1);
            if (h['feature_enabled[' + i + '][' + j + ']']) {
              h['feature_value[' + i + '][' + j + ']'] = bs.u(segmentation_feature_bits[j]);
              if (h['feature_value[' + i + '][' + j + ']'])
                h['feature_sign[' + i + '][' + j + ']'] = bs.u(1);
            }
          }
        }
      }
    }
  }

  if ('frame_width_minus_1' in h) {
    h['@FrameWidth'] = h['frame_width_minus_1'] + 1;
    h['@FrameHeight'] = h['frame_height_minus_1'] + 1;
  } else {
    var ref = this.find_ref(ref_idx);
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
  while ((64 << minLog2TileCols) < Sb64Cols)
    minLog2TileCols++;
  var maxLog2TileCols = 0;
  while ((Sb64Cols >> (maxLog2TileCols + 1)) >= 4)
    maxLog2TileCols++;
  var tile_cols_log2 = minLog2TileCols;
  for (var i = 0; tile_cols_log2 < maxLog2TileCols; i++) {
    h['increment_tile_cols_log2[' + i + ']'] = bs.u(1);
    if (h['increment_tile_cols_log2[' + i + ']'])
      tile_cols_log2++;
    else
      break;
  }
  h['tile_rows_log2'] = bs.u(1);
  if (h['tile_rows_log2'])
    h['increment_tile_rows_log2'] = bs.u(1);

  h['header_size_in_bytes'] = bs.u(16);

  h['@addr'] = addr;
  h['@type'] = h['frame_type'] == 0 ? 'I' : 'P';
  h['@length'] = buffer.length;
  h['@keyframe'] = 1 - h['frame_type'];
  h['@extra'] = 'QP ' + h['base_q_idx'];
  this.store(h);
}

bitstream_parser_vp9.prototype.color_config = function (h, bs) {
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

  if (h['profile'] >= 2)
    h['ten_or_twelve_bit'] = bs.u(1);
  h['color_space'] = color_space[bs.u(3)];
  if (h['color_space'] != 'CS_RGB')
    h['color_range'] = bs.u(1);
  if (h['profile'] == 1 || h['profile'] == 3) {
    if (h['color_space'] != 'CS_RGB') {
      h['subsampling_x'] = bs.u(1);
      h['subsampling_y'] = bs.u(1);
    }
    h['reserved_zero'] = bs.u(1);
  }
}

bitstream_parser_vp9.prototype.find_ref = function (idx) {
  for (var i = this.header.length - 1; i >= 0; i--) {
    if (!('refresh_frame_flags' in this.header[i])
      || this.header[i]['refresh_frame_flags'] & (1 << idx))
      return this.header[i];
  }
  return null;
}

function bitstream_parser_av1(idoff) {
  bitstream_parser_base.call(this, idoff);
}

bitstream_parser_av1.prototype = new bitstream_parser_base();
bitstream_parser_av1.prototype.parse = function (buffer, addr) {
  var bs = new bitstream(buffer);
  var h = {};
  h['frame_marker'] = bs.u(2);
  h['profile'] = bs.u(2);
  if (h['profile'] > 2)
    h['profile'] += bs.u(1);
  h['show_existing_frames'] = bs.u(1);
  if (h['show_existing_frames'])
    h['frame_to_show_map_idx'] = bs.u(3);
  h['frame_type'] = bs.u(1);
  h['show_frame'] = bs.u(1);
  h['error_resilient_mode'] = bs.u(1);
  h['current_frame_id'] = bs.u(15);
  h['@addr'] = addr;
  h['@type'] = h['frame_type'] == 0 ? 'I' : 'P';
  h['@length'] = buffer.length;
  h['@keyframe'] = 1 - h['frame_type'];
  this.store(h);
}

function bitstream_parser_h264(idoff) {
  bitstream_parser_base.call(this, idoff);
  this.nal_unit_type = ['Unknown'
    , 'Slice'
    , 'DP A'
    , 'DP B'
    , 'DP C'
    , 'IDR'
    , 'SEI'
    , 'SPS'
    , 'PPS'
    , 'AUD'
    , 'End of sequence'
    , 'End of stream'
    , 'Filler data'
    , 'SPS extension'
    , 'Prefix NAL unit'
    , 'Subset SPS'
    , 'Reserved'
    , 'Reserved'
    , 'Reserved'
    , 'Auxiliary slice'
    , 'Slice extension'
    , 'Slice multiview'
    , 'Reserved'
    , 'Reserved'
    , 'Unknown'
    , 'Unknown'
    , 'Unknown'
    , 'Unknown'
    , 'Unknown'
    , 'Unknown'
    , 'Unknown'
    , 'Unknown'
  ];
}

bitstream_parser_h264.prototype = new bitstream_parser_base();
bitstream_parser_h264.prototype.parse = function (buffer, addr) {
  var bs = new bitstream(buffer);
  var h = this.parse_nalu(bs);
  if (h['nal_unit_type'] == 7) {
    this.parse_sps(bs, h);
    h['@extra'] = (h['pic_width_in_mbs_minus1'] + 1) * 16 + 'x' +
      (2 - h['frame_mbs_only_flag']) * (h['pic_height_in_map_units_minus1'] + 1) * 16;
    h['@extra'] += ' ' + this.profile(h);
    h['@extra'] += ' ' + h['level_idc'] / 10;
  } else if (h['nal_unit_type'] == 8) {
    this.parse_pps(bs, h);
    h['@extra'] = h['entropy_coding_mode_flag'] ? 'CABAC' : 'CAVLC';
  } else if (in_range(h['nal_unit_type'], [1, 5, 20])) {
    this.parse_slice(bs, h);
    h['@type'] = ['P', 'B', 'I', 'SP', 'SI'][h['slice_type'] % 5];
    h['@keyframe'] = h['nal_unit_type'] == 5 || (h['idr_flag'] || 0);
  }
  h['@addr'] = addr;
  if (!in_range(h['nal_unit_type'], [1, 5, 20]))
    h['@type'] = this.nal_unit_type[h['nal_unit_type']];
  h['@length'] = buffer.length;
  this.store(h);
}

bitstream_parser_h264.prototype.find_nalu = function (type, key, value) {
  for (var i = this.header.length - 1; i >= 0; i--) {
    if (in_range(this.header[i]['nal_unit_type'], type)) {
      if (key == null)
        return this.header[i];
      else if (this.header[i][key] == value)
        return this.header[i];
    }
  }
  return null;
}

bitstream_parser_h264.prototype.profile = function (sps) {
  var profile_idc = {
    66: 'Baseline', 77: 'Main', 88: 'Extended', 100: 'High', 110: 'High 10',
    122: 'High 4:2:2', 244: 'High 4:4:4 Predictive', 83: 'Scalable Baseline',
    86: 'Scalable High'
  };

  profile = sps['profile_idc'] in profile_idc ?
    profile_idc[sps['profile_idc']] : 'Unknown';
  if (sps['profile_idc'] == 66) {
    if (sps['constraint_set0_flag'] == 1)
      profile = 'Constrained ' + profile;
  } else if (sps['profile_idc'] == 100) {
    if ((sps['constraint_set4_flag'] == 1
      && sps['constraint_set5_flag'] == 1))
      profile = 'Constrained ' + profile;
  } else if (sps['profile_idc'] == 110) {
    if (sps['constraint_set3_flag'] == 1)
      profile += ' Intra';
  } else if (sps['profile_idc'] == 83) {
    if (sps['constraint_set5_flag'] == 1)
      profile = 'Scalable Constrained Baseline';
  } else if (sps['profile_idc'] == 86) {
    if (sps['constraint_set5_flag'] == 1)
      profile = 'Scalable Constrained High';
  }
  return profile;
}

bitstream_parser_h264.prototype.parse_nalu = function (bs) {
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
      nalu['reserved_three_2bits'] = int2str(bs.u(2), 2, 2, '0');
    }
  }
  return nalu;
}

bitstream_parser_h264.prototype.parse_sps = function (bs, sps) {
  sps['profile_idc'] = bs.u(8);
  sps['constraint_set0_flag'] = bs.u(1);
  sps['constraint_set1_flag'] = bs.u(1);
  sps['constraint_set2_flag'] = bs.u(1);
  sps['constraint_set3_flag'] = bs.u(1);
  sps['constraint_set4_flag'] = bs.u(1);
  sps['constraint_set5_flag'] = bs.u(1);
  sps['reserved_zero_2bits'] = int2str(bs.u(2), 2, 2, '0');
  sps['level_idc'] = bs.u(8);
  sps['seq_parameter_set_id'] = bs.ue();
  if (in_range(sps['profile_idc'], [100, 110, 122, 244, 44, 83, 86, 118, 128])) {
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
          sps['seq_scaling_list_present_flag[' + i + ']'] = this.scaling_list(bs, n * n);
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
    if (sps['nal_hrd_parameters_present_flag'] || sps['vcl_hrd_parameters_present_flag'])
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
}

bitstream_parser_h264.prototype.parse_hrd = function(bs) {
  var hrd = {};
  hrd['cpb_cnt_minus1'] = bs.ue();
  hrd['bit_rate_scale'] = bs.u(4);
  hrd['cpb_size_scale'] = bs.u(4);
  for (var i = 0; i < hrd['cpb_cnt_minus1'] + 1; i++) {
      hrd['bit_rate_value_minus1['+i+']'] = bs.ue();
      hrd['cpb_size_value_minus1['+i+']'] = bs.ue();
      hrd['cbr_flag['+i+']'] = bs.u(1);
  }
  hrd['initial_cpb_removal_delay_length_minus1'] = bs.u(5);
  hrd['cpb_removal_delay_length_minus1'] = bs.u(5);
  hrd['dpb_output_delay_length_minus1'] = bs.u(5);
  hrd['time_offset_length'] = bs.u(5);
  return hrd;
}

bitstream_parser_h264.prototype.parse_pps = function (bs, pps) {
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
      sps = this.find_nalu([7, 15], 'seq_parameter_set_id', pps['seq_parameter_set_id']);
      nlists = 6;
      if (sps)
        nlists += ('chroma_format_idc' in sps && sps['chroma_format_idc'] == 3) ? 6 * pps['transform_8x8_mode_flag'] : 2 * pps['transform_8x8_mode_flag'];
      for (var i = 0; i < nlists; i++) {
        pps['pic_scaling_list_present_flag[' + i + ']'] = bs.u(1);
        if (pps['pic_scaling_list_present_flag[' + i + ']']) {
          var n = i < 6 ? 4 : 8;
          pps['pic_scaling_list_present_flag[' + i + ']'] = this.scaling_list(bs, n * n);
        }
      }
    }
  }
}

bitstream_parser_h264.prototype.parse_slice = function (bs, sh) {
  sh['first_mb_in_slice'] = bs.ue();
  sh['slice_type'] = bs.ue();
  sh['pic_parameter_set_id'] = bs.ue();
  var pps = this.find_nalu([8], 'pic_parameter_set_id', sh['pic_parameter_set_id']);
  if (pps == null)
    return sh;

  var sps = this.find_nalu(sh['nal_unit_type'] == 20 ? [15] : [7], 'seq_parameter_set_id', pps['seq_parameter_set_id']);
  if (sps == null)
    return sh;

  if ('separate_colour_plane_flag' in sps
    && sps['separate_colour_plane_flag'] == 1)
    sh['colour_plane_id'] = bs.u(2);

  sh['frame_num'] = bs.u(sps['log2_max_frame_num_minus4'] + 4);

  if (sps['frame_mbs_only_flag'] == 0) {
    sh['field_pic_flag'] = bs.u(1);
    if (sh['field_pic_flag'])
      sh['bottom_field_flag'] = bs.u(1);
  }

  if (sh['nal_unit_type'] == 5 || ('idr_flag' in sh && sh['idr_flag'] == 1))
    sh['idr_pic_id'] = bs.ue();

  if (sps['pic_order_cnt_type'] == 0) {
    sh['pic_order_cnt_lsb'] = bs.u(sps['log2_max_pic_order_cnt_lsb_minus4'] + 4);
    if (pps['bottom_field_pic_order_in_frame_present_flag'] == 1
      && (!('field_pic_flag' in sh) || sh['field_pic_flag'] == 0))
      sh['delta_pic_order_cnt_bottom'] = bs.se();
  } else if (sps['pic_order_cnt_type'] == 1 && sps['delta_pic_order_always_zero_flag'] == 0) {
    sh['delta_pic_order_cnt[0]'] = bs.se();
    if (pps['bottom_field_pic_order_in_frame_present_flag']
      && 'field_pic_flag' in sh && sh['field_pic_flag'] == 0)
      sh['delta_pic_order_cnt[1]'] = bs.se();
  }

  if (pps['redundant_pic_cnt_present_flag'] == 1)
    sh['redundant_pic_cnt'] = bs.ue();

  if (!('quality_id' in sh) || sh['quality_id'] == 0) {
    if (sh['slice_type'] % 5 == 1)
      sh['direct_spatial_mv_pred_flag'] = bs.u(1);

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
            //todo: add command name
            sh['modification_of_pic_nums_idc_l' + list + '[' + i + ']'] = modification_of_pic_nums_idc;
            if (in_range(modification_of_pic_nums_idc, [0, 1]))
              sh['abs_diff_pic_num_minus1_l' + list + '[' + i + ']'] = bs.ue();
            else if (modification_of_pic_nums_idc == 2)
              sh['long_term_pic_num_l' + list + '[' + i + ']'] = bs.ue();
            i += 1;
          }
        }
      }
    }

    if ((pps['weighted_pred_flag'] && in_range(sh['slice_type'] % 5, [0, 3]))
      || (pps['weighted_bipred_idc'] == 1 && sh['slice_type'] % 5 == 1)) {
      sh['luma_log2_weight_denom'] = bs.ue();
      if (!('chroma_format_idc' in sps) || sps['chroma_format_idc'] != 0)
        sh['chroma_log2_weight_denom'] = bs.ue();
      for (var list = 0; list < (sh['slice_type'] % 5 == 1 ? 2 : 1); list++) {
        var num_ref_idx_active_minus1 = pps['num_ref_idx_l' + list + '_default_active_minus1'];
        if ('num_ref_idx_l' + list + '_active_minus1' in sh)
          var num_ref_idx_active_minus1 = sh['num_ref_idx_l' + list + '_active_minus1'];
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
                sh['chroma_weight_l' + list + '[' + i + ']' + '[' + j + ']'] = bs.se();
                sh['chroma_offset_l' + list + '[' + i + ']' + '[' + j + ']'] = bs.se();
              }
            }
          }
        }
      }
    }

    if (sh['nal_ref_idc'] != 0) {
      if (sh['nal_unit_type'] == 5 || ('idr_flag' in sh && sh['idr_flag'] == 1)) {
        sh['no_output_of_prior_pics_flag'] = bs.u(1);
        sh['long_term_reference_flag'] = bs.u(1);
      } else {
        sh['adaptive_ref_pic_marking_mode_flag'] = bs.u(1);
        if (sh['adaptive_ref_pic_marking_mode_flag']) {
          var i = 0;
          var memory_management_control_operation = 1;
          while (memory_management_control_operation != 0) {
            memory_management_control_operation = bs.ue();
            sh['memory_management_control_operation[' + i + ']'] = memory_management_control_operation;
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

      if ('slice_header_restriction_flag' in sps
        && sps['slice_header_restriction_flag'] == 0) {
        sh['store_ref_base_pic_flag'] = bs.u(1);
        if (sh['use_ref_base_pic_flag'] || sh['store_ref_base_pic_flag']
          && sh['idr_flag'] == 0) {
          sh['adaptive_ref_base_pic_marking_mode_flag'] = bs.u(1);
          if (sh['adaptive_ref_base_pic_marking_mode_flag']) {
            var i = 0;
            var memory_management_base_control_operation = 1;
            while (memory_management_base_control_operation != 0) {
              memory_management_base_control_operation = bs.ue();
              //todo: describe command
              sh['memory_management_base_control_operation[' + i + ']'] = memory_management_control_operation;
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

  if (pps['entropy_coding_mode_flag'] && !in_range(sh['slice_type'] % 5, [2, 4]))
    sh['cabac_init_idc'] = bs.ue();

  sh['slice_qp_delta'] = bs.se();
  if (in_range(sh['slice_type'], [3, 4])) {
    if (sh['slice_type'] == 3)
      sh['sp_for_switch_flag'] = bs.u(1);
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
      if ('adaptive_tcoeff_level_prediction_flag' in sps
        && sps['adaptive_tcoeff_level_prediction_flag'] == 1)
        sh['default_residual_prediction_flag'] = bs.u(1);
    }

    if (sps['slice_header_restriction_flag'] == 0
      && (!('slice_skip_flag' in sh) || sh['slice_skip_flag'] == 0)) {
      sh['scan_idx_start'] = bs.u(4);
      sh['scan_idx_end'] = bs.u(4);
    }
  }
}