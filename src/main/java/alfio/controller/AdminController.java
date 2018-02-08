/**
 * This file is part of alf.io.
 *
 * alf.io is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * alf.io is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with alf.io.  If not, see <http://www.gnu.org/licenses/>.
 */
package alfio.controller;

import java.security.Principal;

import alfio.manager.system.ConfigurationManager;
import alfio.manager.user.UserManager;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@AllArgsConstructor
@RequestMapping("/admin")
public class AdminController {

    private final ConfigurationManager configurationManager;
    private final UserManager userManager;

    //catch both "/admin" and "/admin/"
    @RequestMapping("")
    public String adminHome(Model model, @Value("${alfio.version}") String version, Principal principal) {
        model.addAttribute("alfioVersion", version);
        model.addAttribute("username", principal.getName());
        model.addAttribute("basicConfigurationNeeded", configurationManager.isBasicConfigurationNeeded());
        //TODO not neccessary via OAuth
        model.addAttribute("isAdmin", ((OAuth2Authentication) principal).getAuthorities().contains("ROLE_ADMIN"));
        model.addAttribute("isOwner", ((OAuth2Authentication) principal).getAuthorities().contains("ROLE_OWNER"));
        return "/admin/index";
    }
}
