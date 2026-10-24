import { store } from '../state.js';
import { PAGE_STEP } from '../constants.js';
import { renderAllLogsTable } from '../render/renderAllLogsTable.js';

export function showMoreAll() {
  store.allLimit += PAGE_STEP;
  renderAllLogsTable();
}
