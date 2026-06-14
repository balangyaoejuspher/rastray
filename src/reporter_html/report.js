(function () {
  var filter = document.getElementById('filter');
  var table = document.getElementById('findings-table');
  if (!table) { return; }
  var tbody = table.tBodies[0];
  var rows = Array.from(tbody.rows);
  var chips = document.querySelectorAll('.chip');
  var headers = table.querySelectorAll('th.sortable');
  var activeSeverity = 'all';
  var sortKey = null;
  var sortAsc = true;

  function applyFilter() {
    var needle = (filter.value || '').toLowerCase();
    rows.forEach(function (row) {
      var sev = row.getAttribute('data-severity');
      var matchesSev = activeSeverity === 'all' || sev === activeSeverity;
      var matchesText = !needle || row.textContent.toLowerCase().indexOf(needle) !== -1;
      row.classList.toggle('hidden', !(matchesSev && matchesText));
    });
  }

  filter.addEventListener('input', applyFilter);

  chips.forEach(function (chip) {
    chip.addEventListener('click', function () {
      chips.forEach(function (c) { c.classList.remove('active'); });
      chip.classList.add('active');
      activeSeverity = chip.getAttribute('data-severity');
      applyFilter();
    });
  });

  var severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  function valueFor(row, key) {
    if (key === 'severity') {
      var s = row.getAttribute('data-severity');
      return severityOrder[s] != null ? severityOrder[s] : 99;
    }
    return row.getAttribute('data-' + key) || '';
  }

  headers.forEach(function (th) {
    th.addEventListener('click', function () {
      var key = th.getAttribute('data-key');
      sortAsc = sortKey === key ? !sortAsc : true;
      sortKey = key;
      headers.forEach(function (h) { h.classList.remove('sort-asc', 'sort-desc'); });
      th.classList.add(sortAsc ? 'sort-asc' : 'sort-desc');
      var sorted = rows.slice().sort(function (a, b) {
        var av = valueFor(a, key);
        var bv = valueFor(b, key);
        if (av < bv) { return sortAsc ? -1 : 1; }
        if (av > bv) { return sortAsc ? 1 : -1; }
        return 0;
      });
      sorted.forEach(function (row) { tbody.appendChild(row); });
    });
  });
})();
