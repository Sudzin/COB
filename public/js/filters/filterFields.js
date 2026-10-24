/**
 * Описание выпадающих фильтров. Чтобы добавить новый фильтр,
 * достаточно описать поле здесь и добавить его в нужный список в filterBars.js.
 * Значения подтягиваются из самих логов.
 */
export const F_IP = { key: 'ip', label: 'IP-адрес', get: r => r.ip };
export const F_USER = { key: 'user', label: 'Пользователь', get: r => r.user };
export const F_SERVICE = { key: 'service', label: 'Служба', get: r => r.service };
export const F_HOST = { key: 'host', label: 'Узел', hideSingle: true, get: r => r.host };
export const F_FILE = { key: 'fileName', label: 'Файл', get: r => r.fileName };
