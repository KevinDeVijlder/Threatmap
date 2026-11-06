/**
 * ISO 3166-1 Numeric Country Lookup & Metadata Resolver
 * =====================================================
 * Maps Natural Earth TopoJSON numeric IDs and fallback names to country
 * names and 2-letter ISO codes for flag rendering and telemetry attribution.
 */

export const COUNTRY_LOOKUP = {
  4: { name: "Afghanistan", code: "af" },
  8: { name: "Albania", code: "al" },
  12: { name: "Algeria", code: "dz" },
  16: { name: "American Samoa", code: "as" },
  20: { name: "Andorra", code: "ad" },
  24: { name: "Angola", code: "ao" },
  28: { name: "Antigua and Barbuda", code: "ag" },
  31: { name: "Azerbaijan", code: "az" },
  32: { name: "Argentina", code: "ar" },
  36: { name: "Australia", code: "au" },
  40: { name: "Austria", code: "at" },
  44: { name: "Bahamas", code: "bs" },
  48: { name: "Bahrain", code: "bh" },
  50: { name: "Bangladesh", code: "bd" },
  51: { name: "Armenia", code: "am" },
  52: { name: "Barbados", code: "bb" },
  56: { name: "Belgium", code: "be" },
  60: { name: "Bermuda", code: "bm" },
  64: { name: "Bhutan", code: "bt" },
  68: { name: "Bolivia", code: "bo" },
  70: { name: "Bosnia and Herzegovina", code: "ba" },
  72: { name: "Botswana", code: "bw" },
  76: { name: "Brazil", code: "br" },
  84: { name: "Belize", code: "bz" },
  90: { name: "Solomon Islands", code: "sb" },
  96: { name: "Brunei", code: "bn" },
  100: { name: "Bulgaria", code: "bg" },
  104: { name: "Myanmar", code: "mm" },
  108: { name: "Burundi", code: "bi" },
  112: { name: "Belarus", code: "by" },
  116: { name: "Cambodia", code: "kh" },
  120: { name: "Cameroon", code: "cm" },
  124: { name: "Canada", code: "ca" },
  132: { name: "Cape Verde", code: "cv" },
  140: { name: "Central African Republic", code: "cf" },
  144: { name: "Sri Lanka", code: "lk" },
  148: { name: "Chad", code: "td" },
  152: { name: "Chile", code: "cl" },
  156: { name: "China", code: "cn" },
  158: { name: "Taiwan", code: "tw" },
  170: { name: "Colombia", code: "co" },
  174: { name: "Comoros", code: "km" },
  178: { name: "Republic of the Congo", code: "cg" },
  180: { name: "DR Congo", code: "cd" },
  188: { name: "Costa Rica", code: "cr" },
  191: { name: "Croatia", code: "hr" },
  192: { name: "Cuba", code: "cu" },
  196: { name: "Cyprus", code: "cy" },
  203: { name: "Czechia", code: "cz" },
  204: { name: "Benin", code: "bj" },
  208: { name: "Denmark", code: "dk" },
  212: { name: "Dominica", code: "dm" },
  214: { name: "Dominican Republic", code: "do" },
  218: { name: "Ecuador", code: "ec" },
  222: { name: "El Salvador", code: "sv" },
  226: { name: "Equatorial Guinea", code: "gq" },
  231: { name: "Ethiopia", code: "et" },
  232: { name: "Eritrea", code: "er" },
  233: { name: "Estonia", code: "ee" },
  238: { name: "Falkland Islands", code: "fk" },
  242: { name: "Fiji", code: "fj" },
  246: { name: "Finland", code: "fi" },
  250: { name: "France", code: "fr" },
  254: { name: "French Guiana", code: "gf" },
  258: { name: "French Polynesia", code: "pf" },
  260: { name: "French Southern Lands", code: "tf" },
  262: { name: "Djibouti", code: "dj" },
  266: { name: "Gabon", code: "ga" },
  268: { name: "Georgia", code: "ge" },
  270: { name: "Gambia", code: "gm" },
  275: { name: "Palestine", code: "ps" },
  276: { name: "Germany", code: "de" },
  288: { name: "Ghana", code: "gh" },
  300: { name: "Greece", code: "gr" },
  304: { name: "Greenland", code: "gl" },
  308: { name: "Grenada", code: "gd" },
  316: { name: "Guam", code: "gu" },
  320: { name: "Guatemala", code: "gt" },
  324: { name: "Guinea", code: "gn" },
  328: { name: "Guyana", code: "gy" },
  332: { name: "Haiti", code: "ht" },
  340: { name: "Honduras", code: "hn" },
  344: { name: "Hong Kong", code: "hk" },
  348: { name: "Hungary", code: "hu" },
  352: { name: "Iceland", code: "is" },
  356: { name: "India", code: "in" },
  360: { name: "Indonesia", code: "id" },
  364: { name: "Iran", code: "ir" },
  368: { name: "Iraq", code: "iq" },
  372: { name: "Ireland", code: "ie" },
  376: { name: "Israel", code: "il" },
  380: { name: "Italy", code: "it" },
  384: { name: "Ivory Coast", code: "ci" },
  388: { name: "Jamaica", code: "jm" },
  392: { name: "Japan", code: "jp" },
  398: { name: "Kazakhstan", code: "kz" },
  400: { name: "Jordan", code: "jo" },
  404: { name: "Kenya", code: "ke" },
  408: { name: "North Korea", code: "kp" },
  410: { name: "South Korea", code: "kr" },
  414: { name: "Kuwait", code: "kw" },
  417: { name: "Kyrgyzstan", code: "kg" },
  418: { name: "Laos", code: "la" },
  422: { name: "Lebanon", code: "lb" },
  426: { name: "Lesotho", code: "ls" },
  428: { name: "Latvia", code: "lv" },
  430: { name: "Liberia", code: "lr" },
  434: { name: "Libya", code: "ly" },
  438: { name: "Liechtenstein", code: "li" },
  440: { name: "Lithuania", code: "lt" },
  442: { name: "Luxembourg", code: "lu" },
  446: { name: "Macao", code: "mo" },
  450: { name: "Madagascar", code: "mg" },
  454: { name: "Malawi", code: "mw" },
  458: { name: "Malaysia", code: "my" },
  462: { name: "Maldives", code: "mv" },
  466: { name: "Mali", code: "ml" },
  470: { name: "Malta", code: "mt" },
  478: { name: "Mauritania", code: "mr" },
  480: { name: "Mauritius", code: "mu" },
  484: { name: "Mexico", code: "mx" },
  492: { name: "Monaco", code: "mc" },
  496: { name: "Mongolia", code: "mn" },
  498: { name: "Moldova", code: "md" },
  499: { name: "Montenegro", code: "me" },
  504: { name: "Morocco", code: "ma" },
  508: { name: "Mozambique", code: "mz" },
  512: { name: "Oman", code: "om" },
  516: { name: "Namibia", code: "na" },
  520: { name: "Nauru", code: "nr" },
  524: { name: "Nepal", code: "np" },
  528: { name: "Netherlands", code: "nl" },
  531: { name: "Curacao", code: "cw" },
  533: { name: "Aruba", code: "aw" },
  540: { name: "New Caledonia", code: "nc" },
  548: { name: "Vanuatu", code: "vu" },
  554: { name: "New Zealand", code: "nz" },
  558: { name: "Nicaragua", code: "ni" },
  562: { name: "Niger", code: "ne" },
  566: { name: "Nigeria", code: "ng" },
  578: { name: "Norway", code: "no" },
  583: { name: "Micronesia", code: "fm" },
  584: { name: "Marshall Islands", code: "mh" },
  585: { name: "Palau", code: "pw" },
  586: { name: "Pakistan", code: "pk" },
  591: { name: "Panama", code: "pa" },
  598: { name: "Papua New Guinea", code: "pg" },
  600: { name: "Paraguay", code: "py" },
  604: { name: "Peru", code: "pe" },
  608: { name: "Philippines", code: "ph" },
  616: { name: "Poland", code: "pl" },
  620: { name: "Portugal", code: "pt" },
  624: { name: "Guinea-Bissau", code: "gw" },
  626: { name: "Timor-Leste", code: "tl" },
  630: { name: "Puerto Rico", code: "pr" },
  634: { name: "Qatar", code: "qa" },
  642: { name: "Romania", code: "ro" },
  643: { name: "Russia", code: "ru" },
  646: { name: "Rwanda", code: "rw" },
  659: { name: "Saint Kitts and Nevis", code: "kn" },
  662: { name: "Saint Lucia", code: "lc" },
  670: { name: "Saint Vincent and the Grenadines", code: "vc" },
  674: { name: "San Marino", code: "sm" },
  678: { name: "Sao Tome and Principe", code: "st" },
  682: { name: "Saudi Arabia", code: "sa" },
  686: { name: "Senegal", code: "sn" },
  688: { name: "Serbia", code: "rs" },
  690: { name: "Seychelles", code: "sc" },
  694: { name: "Sierra Leone", code: "sl" },
  702: { name: "Singapore", code: "sg" },
  703: { name: "Slovakia", code: "sk" },
  704: { name: "Vietnam", code: "vn" },
  705: { name: "Slovenia", code: "si" },
  706: { name: "Somalia", code: "so" },
  710: { name: "South Africa", code: "za" },
  716: { name: "Zimbabwe", code: "zw" },
  724: { name: "Spain", code: "es" },
  728: { name: "South Sudan", code: "ss" },
  729: { name: "Sudan", code: "sd" },
  732: { name: "Western Sahara", code: "eh" },
  740: { name: "Suriname", code: "sr" },
  748: { name: "Eswatini", code: "sz" },
  752: { name: "Sweden", code: "se" },
  756: { name: "Switzerland", code: "ch" },
  760: { name: "Syria", code: "sy" },
  762: { name: "Tajikistan", code: "tj" },
  764: { name: "Thailand", code: "th" },
  768: { name: "Togo", code: "tg" },
  776: { name: "Tonga", code: "to" },
  780: { name: "Trinidad and Tobago", code: "tt" },
  784: { name: "United Arab Emirates", code: "ae" },
  788: { name: "Tunisia", code: "tn" },
  792: { name: "Turkey", code: "tr" },
  795: { name: "Turkmenistan", code: "tm" },
  798: { name: "Tuvalu", code: "tv" },
  800: { name: "Uganda", code: "ug" },
  804: { name: "Ukraine", code: "ua" },
  807: { name: "North Macedonia", code: "mk" },
  818: { name: "Egypt", code: "eg" },
  826: { name: "United Kingdom", code: "gb" },
  834: { name: "Tanzania", code: "tz" },
  840: { name: "United States", code: "us" },
  854: { name: "Burkina Faso", code: "bf" },
  858: { name: "Uruguay", code: "uy" },
  860: { name: "Uzbekistan", code: "uz" },
  862: { name: "Venezuela", code: "ve" },
  882: { name: "Samoa", code: "ws" },
  887: { name: "Yemen", code: "ye" },
  894: { name: "Zambia", code: "zm" },
  234: { name: "Faroe Islands", code: "fo" },
  292: { name: "Gibraltar", code: "gi" },
  296: { name: "Kiribati", code: "ki" },
  336: { name: "Vatican City", code: "va" },
};

export const NAME_FALLBACK_LOOKUP = {
  "Kosovo": { name: "Kosovo", code: "xk" },
  "Somaliland": { name: "Somaliland", code: "so" },
  "N. Cyprus": { name: "Northern Cyprus", code: "cy" },
  "W. Sahara": { name: "Western Sahara", code: "eh" },
  "Falkland Is.": { name: "Falkland Islands", code: "fk" },
  "Fr. S. Antarctic Lands": { name: "French Southern Lands", code: "tf" },
};

/**
 * Smaller countries, microstates, and island nations omitted from 1:110m world-atlas,
 * revealed dynamically when the operator zooms into the map.
 */
export const SMALL_COUNTRIES_CATALOG = [
  { id: 702, name: "Singapore", code: "sg", lat: 1.3521, lon: 103.8198, rx: 0.22, ry: 0.14 },
  { id: 48, name: "Bahrain", code: "bh", lat: 26.0667, lon: 50.5577, rx: 0.16, ry: 0.24 },
  { id: 470, name: "Malta", code: "mt", lat: 35.9375, lon: 14.3754, rx: 0.18, ry: 0.14 },
  { id: 20, name: "Andorra", code: "ad", lat: 42.5063, lon: 1.5218, rx: 0.16, ry: 0.14 },
  { id: 438, name: "Liechtenstein", code: "li", lat: 47.166, lon: 9.5554, rx: 0.11, ry: 0.16 },
  { id: 492, name: "Monaco", code: "mc", lat: 43.7384, lon: 7.4246, rx: 0.09, ry: 0.08 },
  { id: 674, name: "San Marino", code: "sm", lat: 43.9424, lon: 12.4578, rx: 0.1, ry: 0.1 },
  { id: 336, name: "Vatican City", code: "va", lat: 41.9029, lon: 12.4534, rx: 0.07, ry: 0.07 },
  { id: 292, name: "Gibraltar", code: "gi", lat: 36.1408, lon: -5.3536, rx: 0.09, ry: 0.09 },
  { id: 344, name: "Hong Kong", code: "hk", lat: 22.3193, lon: 114.1694, rx: 0.24, ry: 0.2 },
  { id: 446, name: "Macao", code: "mo", lat: 22.1987, lon: 113.5439, rx: 0.11, ry: 0.11 },
  { id: 462, name: "Maldives", code: "mv", lat: 3.2028, lon: 73.2207, rx: 0.32, ry: 0.65 },
  { id: 480, name: "Mauritius", code: "mu", lat: -20.3484, lon: 57.5522, rx: 0.25, ry: 0.28 },
  { id: 690, name: "Seychelles", code: "sc", lat: -4.6796, lon: 55.492, rx: 0.26, ry: 0.24 },
  { id: 174, name: "Comoros", code: "km", lat: -11.6455, lon: 43.3333, rx: 0.28, ry: 0.26 },
  { id: 132, name: "Cape Verde", code: "cv", lat: 16.0021, lon: -24.0132, rx: 0.42, ry: 0.38 },
  { id: 678, name: "Sao Tome and Principe", code: "st", lat: 0.1864, lon: 6.6131, rx: 0.22, ry: 0.25 },
  { id: 52, name: "Barbados", code: "bb", lat: 13.1939, lon: -59.5432, rx: 0.18, ry: 0.22 },
  { id: 662, name: "Saint Lucia", code: "lc", lat: 13.9094, lon: -60.9789, rx: 0.16, ry: 0.22 },
  { id: 308, name: "Grenada", code: "gd", lat: 12.1165, lon: -61.679, rx: 0.16, ry: 0.18 },
  { id: 670, name: "Saint Vincent and the Grenadines", code: "vc", lat: 12.9843, lon: -61.2872, rx: 0.15, ry: 0.2 },
  { id: 28, name: "Antigua and Barbuda", code: "ag", lat: 17.0608, lon: -61.7964, rx: 0.18, ry: 0.18 },
  { id: 212, name: "Dominica", code: "dm", lat: 15.415, lon: -61.371, rx: 0.16, ry: 0.22 },
  { id: 659, name: "Saint Kitts and Nevis", code: "kn", lat: 17.3578, lon: -62.783, rx: 0.16, ry: 0.16 },
  { id: 531, name: "Curacao", code: "cw", lat: 12.1696, lon: -68.99, rx: 0.22, ry: 0.14 },
  { id: 533, name: "Aruba", code: "aw", lat: 12.5211, lon: -69.9683, rx: 0.16, ry: 0.13 },
  { id: 60, name: "Bermuda", code: "bm", lat: 32.3078, lon: -64.7505, rx: 0.18, ry: 0.14 },
  { id: 234, name: "Faroe Islands", code: "fo", lat: 61.8926, lon: -6.9118, rx: 0.32, ry: 0.38 },
  { id: 882, name: "Samoa", code: "ws", lat: -13.759, lon: -172.1046, rx: 0.35, ry: 0.22 },
  { id: 776, name: "Tonga", code: "to", lat: -21.179, lon: -175.1982, rx: 0.24, ry: 0.35 },
  { id: 585, name: "Palau", code: "pw", lat: 7.515, lon: 134.5825, rx: 0.22, ry: 0.28 },
  { id: 583, name: "Micronesia", code: "fm", lat: 6.8874, lon: 158.215, rx: 0.35, ry: 0.28 },
  { id: 584, name: "Marshall Islands", code: "mh", lat: 7.1315, lon: 171.1845, rx: 0.32, ry: 0.32 },
  { id: 296, name: "Kiribati", code: "ki", lat: 1.4518, lon: 172.9717, rx: 0.34, ry: 0.3 },
  { id: 520, name: "Nauru", code: "nr", lat: -0.5228, lon: 166.9315, rx: 0.16, ry: 0.16 },
  { id: 798, name: "Tuvalu", code: "tv", lat: -8.5211, lon: 179.1962, rx: 0.2, ry: 0.22 },
  { id: 316, name: "Guam", code: "gu", lat: 13.4443, lon: 144.7937, rx: 0.18, ry: 0.24 },
  { id: 258, name: "French Polynesia", code: "pf", lat: -17.6797, lon: -149.4068, rx: 0.38, ry: 0.3 },
  { id: 16, name: "American Samoa", code: "as", lat: -14.271, lon: -170.1322, rx: 0.22, ry: 0.16 },
];

/**
 * Generates GeoJSON Polygon features for smaller countries not already present
 * in the base 1:110m TopoJSON dataset.
 */
export function buildSmallCountryFeatures(existingIdsSet) {
  const features = [];
  const vertices = 12;

  for (const item of SMALL_COUNTRIES_CATALOG) {
    if (existingIdsSet && existingIdsSet.has(item.id)) continue;

    const ring = [];
    for (let i = 0; i < vertices; i++) {
      const angle = (i / vertices) * Math.PI * 2;
      const wobble = 1 + 0.1 * Math.sin(i * 3.1 + item.id);
      const lon = item.lon + Math.cos(angle) * item.rx * wobble;
      const lat = item.lat + Math.sin(angle) * item.ry * wobble;
      ring.push([lon, lat]);
    }

    features.push({
      type: "Feature",
      id: String(item.id),
      isSmallCountry: true,
      centerLon: item.lon,
      centerLat: item.lat,
      rx: item.rx,
      ry: item.ry,
      ring,
      properties: {
        name: item.name,
        code: item.code,
      },
    });
  }

  return features;
}

export function getCountryMeta(feature) {
  if (!feature) return null;
  const numericId = parseInt(feature.id, 10);
  if (!Number.isNaN(numericId) && COUNTRY_LOOKUP[numericId]) {
    return {
      name: COUNTRY_LOOKUP[numericId].name,
      code: COUNTRY_LOOKUP[numericId].code,
      idLabel: numericId,
    };
  }

  const propName =
    feature.properties && feature.properties.name
      ? feature.properties.name.trim()
      : "";
  if (propName && NAME_FALLBACK_LOOKUP[propName]) {
    return {
      name: NAME_FALLBACK_LOOKUP[propName].name,
      code: NAME_FALLBACK_LOOKUP[propName].code,
      idLabel: Number.isNaN(numericId) ? "EXT" : numericId,
    };
  }

  if (propName) {
    return {
      name: propName,
      code: null,
      idLabel: Number.isNaN(numericId) ? "EXT" : numericId,
    };
  }

  return null;
}
