import { User } from "../lib/api";
import ProfileButton from "./profile";

function NavigationBar({ user }: { user: User }) {
  let role = user.role?.name;
  return (
    <div className="flex justify-start items-center p-4 bg-background">
      <h1 className="text-2xl font-bold">ITSM X</h1>
      {role === "admin" && (
        <div>
          <div>Tickets</div>
          <div>Change Management</div>
          <div>CMDB</div>
          <div>System Administration</div>
        </div>
      )}
      {role === "manager" && (
        <div>
          <div>Tickets</div>
          <div>Change Management</div>
          <div>CMDB</div>
        </div>
      )}
      {role === "agent" && (
        <div>
          <div>Tickets</div>
          <div>Change Management</div>
          <div>CMDB</div>
        </div>
      )}
      {role === "user" && (
        <div>
          <div>Tickets</div>
          <div>Change Management</div>
          <div>CMDB</div>
          <div>Settings</div>
        </div>
      )}
      <ProfileButton user={user} />
    </div>
  );
}

export default NavigationBar;
