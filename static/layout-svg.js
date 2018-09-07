function hexColorToRGB(hex) {

  hex = hex.replace(/^#/, '');

  // ignore alpha channel
  if (hex.length === 8) {
    hex = hex.substring(0, 6);
  }
  if (hex.length === 4) {
    hex = hex.substring(0, 3);
  }

  // Convert 3 char format 6 char format
  if (hex.length === 3) {
    hex = hex[0] + hex[0] + hex[1] + hex[1] + hex[2] + hex[2];
  }

  var num = parseInt(hex, 16);
  var r = ((num >> 16) & 0xFF) / 255.0;
  var g = ((num >> 8) & 0xFF) / 255.0;
  var b = (num & 0xFF) / 255.0;

  return [r, g, b];

}

function hexColortoHSV(hex) {
  var rgb = hexColorToRGB(hex);
  var r = rgb[0];
  var g = rgb[1];
  var b = rgb[2];

  var max = Math.max(r, g, b);
  var min = Math.min(r, g, b);
  var h, s, v = max;

  var d = max - min;
  s = (max == 0) ? 0 : d / max;

  if (max == min) {
    h = 0; // achromatic
  } else {
    switch (max) {
      case r: h = 60 * (((g - b) / d) % 6); break;
      case g: h = 60 * ((b - r) / d + 2); break;
      case b: h = 60 * ((r - g) / d + 4); break;
    }
  }

  return [h, s, v];
}

function set_color($image, color) {
  var hsv = hexColortoHSV(color);

  $image.css('filter',
    // Convert to sepia (make sure S and V aren't 0) and make sure S and V are 100%
    'invert(.5) sepia(1) saturate(100) brightness(100) '+
    // Change to final color based on HSV color
    'hue-rotate('+hsv[0]+'deg) saturate('+hsv[1]+') brightness('+hsv[2]+')'
  );
}

function set_layer_color($layer_color) {
  var layer_id = $layer_color.attr('name').split('-')[0];
  set_color($('#'+layer_id), $layer_color.val());
}

function enable_visibility($visibility_input) {
  var layer_id = $visibility_input.attr('name').split('-')[0];
  var $layer = $('#'+layer_id);

  if ($visibility_input[0].checked) {
    $layer.show();
  } else {
    $layer.hide();
  }
}

$(function() {
  $('input:radio[name=top-layer]').change(function() {
    var top_layer = this.value ;
    $('.layer').each(function() {
      $layer = $(this);
      if ($layer.attr('id') === top_layer) {
        $layer.addClass('top');
      } else {
        $layer.removeClass('top');
      }
    });
  });

  var $color_inputs = $('.layer-color');

  $color_inputs.each(function() {
    set_layer_color($(this));
  });

  $color_inputs.change(function() {
    set_layer_color($(this));
  });

  var $visibility_inputs = $('.layer-visible');

  $visibility_inputs.each(function() {
    enable_visibility($(this));
  });

  $visibility_inputs.change(function() {
    enable_visibility($(this));
  });


  var $layers = $('.layer');
  var ZOOM_SPEED = 0.01;
  var MAXWIDTH = 100000;
  var MINWIDTH = $layers[0].width;
  function zoomLayers($layers, e) {
    var width = $layers[0].width;
    if (e.deltaY < 0) {
      width += width* ZOOM_SPEED*-e.deltaY;
      if (width > MAXWIDTH) width = MAXWIDTH;
    } else {
      width -= width * ZOOM_SPEED*e.deltaY;
      if (width < MINWIDTH) width = MINWIDTH;
    }

    var d = width / $layers[0].width;

    $layers.each(function(_, layer) {
      layer.width = width;
    });

    layout.scrollTop = (layout.scrollTop + e.y)*d - e.y;
    layout.scrollLeft = (layout.scrollLeft + e.x)*d - e.x;
  }

  var layout = document.querySelector('#layout');
  layout.onwheel = function(e) {
    console.log(e);
    if (e.ctrlKey) {
      e.preventDefault();
      zoomLayers($layers, e);
    }
  };

});
