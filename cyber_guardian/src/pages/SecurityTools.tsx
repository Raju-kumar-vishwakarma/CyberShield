import { Layout } from "@/components/Layout";
import { PasswordSecurityTool, IPGeolocationTool, AIThreatIntelligence } from "@/components/SecurityTools";
import { ReportExport } from "@/components/ReportExport";
import { 
  Shield, 
  Key, 
  MapPin, 
  Zap,
  Download
} from "lucide-react";

const SecurityToolsPage = () => {
  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between animate-fade-in">
          <div>
            <h1 className="text-2xl lg:text-3xl font-mono font-bold text-foreground mb-2">
              Security Tools
            </h1>
            <p className="text-muted-foreground">
              AI-powered security analysis, password tools, and threat intelligence
            </p>
          </div>
          <ReportExport />
        </div>

        {/* Tools Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Password Security Tool */}
          <div className="animate-fade-in" style={{ animationDelay: "0.1s" }}>
            <PasswordSecurityTool />
          </div>

          {/* IP Geolocation */}
          <div className="animate-fade-in" style={{ animationDelay: "0.2s" }}>
            <IPGeolocationTool />
          </div>

          {/* AI Threat Intelligence - Full Width */}
          <div className="lg:col-span-2 animate-fade-in" style={{ animationDelay: "0.3s" }}>
            <AIThreatIntelligence />
          </div>
        </div>
      </div>
    </Layout>
  );
};

export default SecurityToolsPage;
