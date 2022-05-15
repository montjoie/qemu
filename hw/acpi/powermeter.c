/*  Emulation of a powermeter
 *
 * Copyright (C) 2022 Corentin Labbe <clabbe@baylibre.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qapi/error.h"

#include "exec/memory.h"
#include "hw/acpi/acpi.h"
#include "hw/acpi/aml-build.h"
#include "hw/acpi/utils.h"
#include "hw/acpi/powermeter.h"
#include "hw/i386/fw_cfg.h"

void acpi_powermeter_add(Aml *scope)
{
    Aml *dev = aml_device("PMT1");
    Aml *method;
    Aml *pkg;

    aml_append(dev, aml_name_decl("_HID", aml_string("ACPI000D")));
    aml_append(dev, aml_name_decl("_UID", aml_int(0)));
    aml_append(dev, aml_name_decl("PMAI", aml_int(666)));
    aml_append(dev, aml_name_decl("HWL", aml_int(333)));
    aml_append(dev, aml_name_decl("PTPL", aml_int(0)));
    aml_append(dev, aml_name_decl("PTPU", aml_int(10)));

    pkg = aml_package(14);
    aml_append(pkg, aml_int(0x1)); /* flags */
    aml_append(pkg, aml_int(0));
    aml_append(pkg, aml_int(0));
    aml_append(pkg, aml_int(0));
    aml_append(pkg, aml_int(1));
    aml_append(pkg, aml_int(0)); /* min */
    aml_append(pkg, aml_int(100)); /* max */
    aml_append(pkg, aml_int(1));
    aml_append(pkg, aml_int(0));
    aml_append(pkg, aml_int(0)); /* min cap */
    aml_append(pkg, aml_int(0)); /* max cap */
    aml_append(pkg, aml_string("QEMU ACPI power meter"));
    aml_append(pkg, aml_string("0"));
    aml_append(pkg, aml_string("QEMU OEM"));
    aml_append(scope, aml_name_decl("PMCP", pkg));

    method = aml_method("_PMC", 0, AML_NOTSERIALIZED);
    aml_append(method, aml_return(aml_name("PMCP")));
    aml_append(dev, method);

    method = aml_method("_PMD", 0, AML_NOTSERIALIZED);
    pkg = aml_package(1);
    aml_append(pkg, aml_name("_SB"));
    aml_append(method, aml_return(pkg));
    aml_append(dev, method);

    method = aml_method("_PMM", 0, AML_NOTSERIALIZED);
    aml_append(method, aml_return(aml_int(40)));
    aml_append(dev, method);

    method = aml_method("_GAI", 0, AML_NOTSERIALIZED);
    aml_append(method, aml_return(aml_name("PMAI")));
    aml_append(method, aml_return(aml_int(4000)));
    aml_append(dev, method);

    method = aml_method("_PAI", 1, AML_NOTSERIALIZED);
    aml_append(method, aml_store(aml_arg(0), aml_name("PMAI")));
    aml_append(method, aml_notify(aml_name("PMT1"), aml_int(0x84)));
    aml_append(method, aml_return(aml_int(0)));
    aml_append(dev, method);

    method = aml_method("_GHL", 0, AML_NOTSERIALIZED);
    aml_append(method, aml_return(aml_name("HWL")));
    aml_append(dev, method);

    method = aml_method("_SHL", 1, AML_NOTSERIALIZED);
    aml_append(method, aml_store(aml_arg(0), aml_name("HWL")));
    aml_append(method, aml_notify(aml_name("PMT1"), aml_int(0x82)));
    aml_append(method, aml_return(aml_int(0)));
    aml_append(dev, method);

    method = aml_method("_PTP", 1, AML_NOTSERIALIZED);
    aml_append(method, aml_store(aml_arg(0), aml_name("PTPU")));
    aml_append(method, aml_store(aml_arg(0), aml_name("PTPL")));
    aml_append(method, aml_return(aml_int(0)));
    aml_append(dev, method);

    aml_append(scope, dev);
}
