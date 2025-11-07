// Enhances course cards with a Details section showing unit-wise topics and completion

function fetchCourseDetails(courseId) {
  const encoded = encodeURIComponent(courseId);
  return fetch(`/api/course/${encoded}/progress`, { credentials: 'include' })
    .then(res => {
      if (!res.ok) {
        if (res.status === 401) {
          window.location.href = '/login';
        }
        throw new Error(`HTTP ${res.status}`);
      }
      return res.json();
    });
}

function renderCourseDetails(details, container) {
  if (!details || !details.detailed_progress) {
    container.innerHTML = '<div class="error">No detailed progress available.</div>';
    return;
  }
  const dp = details.detailed_progress;

  const wrapper = document.createElement('div');
  wrapper.style.background = '#f8f9fa';
  wrapper.style.borderRadius = '10px';
  wrapper.style.padding = '14px';
  wrapper.style.border = '1px solid #e9ecef';

  const overall = document.createElement('div');
  overall.style.marginBottom = '8px';
  const overallPct = Math.round(dp.overall_completion_percentage || 0);
  overall.innerHTML = `<strong>Overall completion:</strong> ${overallPct}% (${dp.overall_completed_count || 0}/${dp.overall_total_count || 0})`;
  wrapper.appendChild(overall);

  const list = document.createElement('div');
  list.style.display = 'grid';
  list.style.gap = '10px';

  (dp.chapters || []).forEach(ch => {
    const chEl = document.createElement('div');
    chEl.style.background = 'white';
    chEl.style.border = '1px solid #eee';
    chEl.style.borderRadius = '8px';
    chEl.style.padding = '10px';

    const chHdr = document.createElement('div');
    chHdr.style.display = 'flex';
    chHdr.style.justifyContent = 'space-between';
    chHdr.style.alignItems = 'center';
    const chPct = Math.round(ch.completion_percentage || 0);
    chHdr.innerHTML = `<div><strong>Chapter:</strong> ${ch.display_name}</div><div>${chPct}%</div>`;
    chEl.appendChild(chHdr);

    (ch.sections || []).forEach(sec => {
      const secEl = document.createElement('div');
      secEl.style.margin = '8px 0 0 10px';
      const secPct = Math.round(sec.completion_percentage || 0);
      secEl.innerHTML = `<div><strong>Section:</strong> ${sec.display_name} - ${secPct}%</div>`;

      (sec.units || []).forEach(unit => {
        const unitEl = document.createElement('div');
        unitEl.style.margin = '6px 0 0 16px';
        const unitPct = Math.round(unit.completion_percentage || 0);
        unitEl.innerHTML = `<div><strong>Unit:</strong> ${unit.display_name} - ${unitPct}%</div>`;

        (unit.components || []).forEach(comp => {
          const compEl = document.createElement('div');
          compEl.style.margin = '4px 0 0 22px';
          compEl.style.display = 'flex';
          compEl.style.gap = '8px';
          const done = comp.completion === 1;
          const badge = `<span style="display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;${done ? 'background:#d4edda;color:#155724' : 'background:#fff3cd;color:#856404'}">${done ? 'Done' : 'Pending'}</span>`;
          compEl.innerHTML = `${badge} <span>${comp.display_name} <em style="color:#888">(${comp.type})</em></span>`;
          unitEl.appendChild(compEl);
        });

        secEl.appendChild(unitEl);
      });

      chEl.appendChild(secEl);
    });

    list.appendChild(chEl);
  });

  wrapper.appendChild(list);
  container.innerHTML = '';
  container.appendChild(wrapper);
}

// Override createCourseCard to render correct progress and include details
window.createCourseCard = function(course) {
  const card = document.createElement('div');
  card.className = 'course-card';

  const completionPercent = Math.round(course.completion_percentage || 0);
  const gradePercent = Math.round((course.grade_percent || 0) * 100);
  const passed = !!course.passed;
  const statusClass = course.is_active ? 'status-active' : 'status-inactive';
  const statusText = course.is_active ? 'Active' : 'Inactive';
  const enrollmentMode = course.enrollment_mode || 'audit';
  const encodedId = encodeURIComponent(course.course_id || '');

  card.innerHTML = `
    <div class="course-header">
      <h2 class="course-name">${course.course_name || 'Untitled Course'}</h2>
      <p class="course-id">${course.course_id || ''}</p>
      <div style="margin-top: 8px;">
        <span class="course-status ${statusClass}">${statusText}</span>
        <span class="enrollment-mode">${enrollmentMode}</span>
      </div>
    </div>

    <div class="progress-section">
      <div class="progress-label">
        <span>Course Progress</span>
        <span class="progress-percent">${completionPercent}%</span>
      </div>
      <div class="progress-bar">
        <div class="progress-fill" style="width: ${completionPercent}%">
          ${completionPercent > 15 ? completionPercent + '%' : ''}
        </div>
      </div>
    </div>

    <div class="grade-section">
      <div class="grade-item">
        <div class="grade-label">Current Grade</div>
        <div class="grade-value">${isNaN(gradePercent) ? 'N/A' : gradePercent + '%'}</div>
      </div>
      <div class="grade-item">
        <div class="grade-label">Status</div>
        <div class="grade-value ${passed ? 'passed' : (isNaN(gradePercent) ? '' : 'failed')}">${
          passed ? 'Passing' : (!isNaN(gradePercent) ? 'Not Passing' : 'N/A')
        }</div>
      </div>
    </div>

    <div style="margin-top: 16px;">
      <button class="refresh-btn" data-course-id="${encodedId}">View details</button>
    </div>
    <div id="details-${encodedId}" class="course-details hidden" style="margin-top: 14px;"></div>
  `;

  // Wire the details button
  const btn = card.querySelector('button.refresh-btn');
  const container = card.querySelector(`#details-${encodedId}`);
  btn.addEventListener('click', async () => {
    if (!container.classList.contains('hidden')) {
      container.classList.add('hidden');
      btn.textContent = 'View details';
      return;
    }
    btn.disabled = true;
    btn.textContent = 'Loading details...';
    try {
      const details = await fetchCourseDetails(course.course_id);
      renderCourseDetails(details, container);
      container.classList.remove('hidden');
      btn.textContent = 'Hide details';
    } catch (e) {
      container.innerHTML = `<div class=\"error\">Failed to load details: ${e.message}</div>`;
      container.classList.remove('hidden');
      btn.textContent = 'View details';
    } finally {
      btn.disabled = false;
    }
  });

  return card;
}

