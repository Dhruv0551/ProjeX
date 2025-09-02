export const userRoles = {
  ADMIN: 'admin',
  PROJECT_ADMIN: 'project_admin',
  MEMBER: 'member',
};

export const availableUserRoles = Object.values(userRoles);

export const taskStatus = {
  TODO: 'todo',
  IN_PROGRESS: 'in_progress',
  DONE: 'done',
};

export default availableTasksStatus = Object.values(taskStatus);
